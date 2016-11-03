# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import logging

from django.conf import settings
from django.contrib import auth
from django.contrib.auth.decorators import login_required  # noqa
from django.contrib.auth import views as django_auth_views
from django.contrib import messages
from django.core.mail import EmailMessage
from django import http as django_http
from django import shortcuts
from django.utils import functional
from django.utils import http
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.cache import never_cache  # noqa
from django.views.decorators.csrf import csrf_exempt  # noqa
from django.views.decorators.csrf import csrf_protect  # noqa
from django.views.decorators.debug import sensitive_post_parameters  # noqa
from keystoneauth1 import exceptions as keystone_exceptions
from keystoneauth1 import token_endpoint
import six

from openstack_auth import exceptions
from openstack_auth import forms
# This is historic and is added back in to not break older versions of
# Horizon, fix to Horizon to remove this requirement was committed in
# Juno
from openstack_auth.forms import Login  # noqa
from openstack_auth import user as auth_user
from openstack_auth import utils

from itsdangerous import URLSafeTimedSerializer
from openstack_user_management.connectors.openstack_connector \
    import OpenstackConnector

import random
import string


try:
    is_safe_url = http.is_safe_url
except AttributeError:
    is_safe_url = utils.is_safe_url


LOG = logging.getLogger(__name__)


@sensitive_post_parameters()
@csrf_protect
@never_cache
def login(request, template_name=None, extra_context=None, **kwargs):
    """Logs a user in using the :class:`~openstack_auth.forms.Login` form."""

    # If the user enabled websso and selects default protocol
    # from the dropdown, We need to redirect user to the websso url
    if request.method == 'POST':

        auth_type = request.POST.get('auth_type', 'credentials')
        if utils.is_websso_enabled() and auth_type != 'credentials':
            auth_url = request.POST.get('region')
            url = utils.get_websso_url(request, auth_url, auth_type)
            return shortcuts.redirect(url)

    if not request.is_ajax():
        # If the user is already authenticated, redirect them to the
        # dashboard straight away, unless the 'next' parameter is set as it
        # usually indicates requesting access to a page that requires different
        # permissions.
        if (request.user.is_authenticated() and
                auth.REDIRECT_FIELD_NAME not in request.GET and
                auth.REDIRECT_FIELD_NAME not in request.POST):
            return shortcuts.redirect(settings.LOGIN_REDIRECT_URL)

    # Get our initial region for the form.
    initial = {}
    current_region = request.session.get('region_endpoint', None)
    requested_region = request.GET.get('region', None)
    regions = dict(getattr(settings, "AVAILABLE_REGIONS", []))
    if requested_region in regions and requested_region != current_region:
        initial.update({'region': requested_region})

    if request.method == "POST":
        form = functional.curry(forms.Login)
    else:
        form = functional.curry(forms.Login, initial=initial)

    if extra_context is None:
        extra_context = {'redirect_field_name': auth.REDIRECT_FIELD_NAME}

    if not template_name:
        if request.is_ajax():
            template_name = 'auth/_login.html'
            extra_context['hide'] = True
        else:
            template_name = 'auth/login.html'

    res = django_auth_views.login(request,
                                  template_name=template_name,
                                  authentication_form=form,
                                  extra_context=extra_context,
                                  **kwargs)
    # Save the region in the cookie, this is used as the default
    # selected region next time the Login form loads.
    if request.method == "POST":
        utils.set_response_cookie(res, 'login_region',
                                  request.POST.get('region', ''))
        utils.set_response_cookie(res, 'login_domain',
                                  request.POST.get('domain', ''))

    # Set the session data here because django's session key rotation
    # will erase it if we set it earlier.
    if request.user.is_authenticated():
        auth_user.set_session_from_user(request, request.user)
        regions = dict(forms.Login.get_region_choices())
        region = request.user.endpoint
        region_name = regions.get(region)
        request.session['region_endpoint'] = region
        request.session['region_name'] = region_name
    return res


@sensitive_post_parameters()
@csrf_exempt
@never_cache
def register(request):
    form = forms.Register()

    if request.method == 'POST':

        registered = ''
        form = forms.Register(request.POST)
        if form.is_valid():

            registered = 'OK'
            univ = request.POST.get('university')
            email = request.POST.get('email')
            username = email
            projectname = username
            projectdescription = projectname + '\'s Project on OpenStack'
            password = request.POST.get('password')
            repassword = request.POST.get('retype_password')

            try:
                client_address = request.META['HTTP_X_FORWARDED_FOR']
            except Exception:
                client_address = request.META['REMOTE_ADDR']

            LOG.info("Client IP: " + client_address)

            if not (projectname and univ and password and repassword):
                registered = 'empty_fields'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            if not (password == repassword):
                registered = 'passwords_not_match'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            if not (len(password) >= 6):
                registered = 'passwords_too_weak'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            if univ not in email:
                registered = 'univ_mail_not_used'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            # TODO(ecelik): also save and log user ip

            conn = OpenstackConnector()
            if not conn.check_username_availability(username):
                registered = 'user_in_use'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            # TODO(ecelik): Get domain name
            if not conn.create_project(
                    "default", projectdescription, projectname,
                    client_address, univ):
                registered = 'openstack_error'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            if not conn.create_user("default", email, username, password):
                registered = 'openstack_error'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            default_role_name = settings.OPENSTACK_KEYSTONE_DEFAULT_ROLE

            if default_role_name is None:
                registered = 'openstack_error'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            if not conn.pair_user_with_project(username, projectname,
                                               default_role_name):
                registered = 'openstack_error'
                return shortcuts.render(
                    request, 'auth/register.html',
                    {'registered': registered, 'form': form})

            if not conn.init_network(projectname,
                                     settings.OPENSTACK_EXT_NET,
                                     settings.OPENSTACK_DNS_NAMESERVERS,
                                     settings.OPENSTACK_DEFAULT_SUBNET_CIDR,
                                     settings.OPENSTACK_DEFAULT_GATEWAY_IP):
                LOG.warning('Network could not be initialized for project ' +
                            projectname + '.')

            send_confirmation_mail(username, email)
    else:
        registered = ''
    return shortcuts.render(
        request, 'auth/register.html',
        {'registered': registered, 'form': form})


def generate_confirmation_token(secret):
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY)
    return serializer.dumps(secret, salt=settings.SECURITY_PASSWORD_SALT)


def confirm_token(token, expiration=3600):
    serializer = URLSafeTimedSerializer(settings.SECRET_KEY)
    try:
        secret = serializer.loads(
            token,
            salt=settings.SECURITY_PASSWORD_SALT,
            max_age=expiration
        )
    except Exception:
        return False
    return secret


def confirm_mail(request, token):
    username = confirm_token(token)
    projectname = username
    if username is False:
        return shortcuts.render(
            request, 'auth/activation.html',
            {'page_title': 'Activation', 'activation': 'FAIL'})
    else:
        # enable user
        activation = 'OK'
        conn = OpenstackConnector()
        if not conn.update_project_status(projectname, True):
            activation = 'openstack_error'
        if not conn.update_user_status(username, True):
            activation = 'openstack_error'

        # TODO(ecelik): send_success_mail(username, email)
        return shortcuts.render(
            request, 'auth/activation.html',
            {'page_title': 'Activation', 'activation': activation})


def forgot_password(request, email):

    username = email

    conn = OpenstackConnector()
    if conn.check_username_availability(username):
        LOG.warning("User not exist in OpenStack: Username: " + username)
        return shortcuts.render(
            request, 'auth/activation.html',
            {'page_title': 'Forgot Password', 'activation': 'FAIL'})

    LOG.info("Resetting password of " + email)

    s = string.lowercase + string.digits
    randpassword = ''.join(random.sample(s, 10))

    if not conn.update_user_password(username, randpassword):
        return shortcuts.render(
            request, 'auth/activation.html',
            {'page_title': 'Forgot Password', 'activation': 'FAIL'})

    send_reset_password_mail(username, email, randpassword)

    return django_http.HttpResponseRedirect(settings.LOGIN_URL)


def resend_confirm_mail(request, email):

    username = email

    conn = OpenstackConnector()
    if conn.check_username_availability(username):
        LOG.warning("User not exist in OpenStack: Username: " + username)
        return shortcuts.render(
            request, 'auth/activation.html',
            {'page_title': 'Activation', 'activation': 'FAIL'})

    LOG.info("Sending confirmation e-mail to " + email)

    send_confirmation_mail(username, email)
    return django_http.HttpResponseRedirect(settings.LOGIN_URL)


def send_confirmation_mail(username, email):

    confirmation_token = generate_confirmation_token(username)
    confirm_url = settings.DOMAIN_URL + "auth/confirm_mail/"
    confirm_url = confirm_url + confirmation_token

    # TODO(ecelik): Use a template for confirmation mail
    subject = "B3LAB OpenStack Registration Confirmation Mail"
    from_email = settings.EMAIL_HOST_USER
    to_list = [email, settings.EMAIL_HOST_USER]

    html_content = '<html>\
            <body>\
                <p>Welcome to B3LAB OpenStack!</p>\
                <br> <br>\
                Your OpenStack username is ' + username + '\
                <br> <br>\
                To finish setting up your OpenStack account, please verify '\
                'your e-mail address by clicking the following link.\
                <br>\
                <a href="' + confirm_url + '">' + confirm_url + '</a>\
                <br> <br>\
                If you did not make this request please ignore this message.\
                <br> <br>\
                Sincerely,\
                <br>\
                B3LAB team\
                <br>\
                <br>\
            </body>\
            </html>'

    msg = EmailMessage(subject, html_content, from_email, to_list)
    msg.content_subtype = "html"
    res = msg.send()

    if str(res) == "1":
        LOG.info("Confirmation email sent successfully.")
    else:
        LOG.error("Confirmation email not sent. " + res)
    return


def send_reset_password_mail(username, email, password):
    subject = "B3LAB OpenStack Reset Password"
    from_email = settings.EMAIL_HOST_USER
    to_list = [email, settings.EMAIL_HOST_USER]

    # TODO(ecelik): Use a template for reset password mail
    html_content = '<html>\
            <body>\
                <p>Welcome to B3LAB OpenStack!</p>\
                <br> <br>\
                Your OpenStack username is ' + username + '\
                <br> <br>\
                Your password has been reset.\
                <br>\
                New Password: ' + password + '\
                <br> <br>\
                You can later change this password from Settings menu.\
                <br> <br>\
                Sincerely,\
                <br>\
                B3LAB team\
                <br>\
                <br>\
            </body>\
            </html>'

    msg = EmailMessage(subject, html_content, from_email, to_list)
    msg.content_subtype = "html"
    res = msg.send()

    if str(res) == "1":
        LOG.info("Reset password email sent successfully.")
    else:
        LOG.error("Reset password email not sent. " + res)
    return


@sensitive_post_parameters()
@csrf_exempt
@never_cache
def websso(request):
    """Logs a user in using a token from Keystone's POST."""
    referer = request.META.get('HTTP_REFERER', settings.OPENSTACK_KEYSTONE_URL)
    auth_url = utils.clean_up_auth_url(referer)
    token = request.POST.get('token')
    try:
        request.user = auth.authenticate(request=request, auth_url=auth_url,
                                         token=token)
    except exceptions.KeystoneAuthException as exc:
        msg = 'Login failed: %s' % six.text_type(exc)
        res = django_http.HttpResponseRedirect(settings.LOGIN_URL)
        res.set_cookie('logout_reason', msg, max_age=10)
        return res

    auth_user.set_session_from_user(request, request.user)
    auth.login(request, request.user)
    if request.session.test_cookie_worked():
        request.session.delete_test_cookie()
    return django_http.HttpResponseRedirect(settings.LOGIN_REDIRECT_URL)


def logout(request, login_url=None, **kwargs):
    """Logs out the user if he is logged in. Then redirects to the log-in page.

    :param login_url:
        Once logged out, defines the URL where to redirect after login

    :param kwargs:
        see django.contrib.auth.views.logout_then_login extra parameters.

    """
    msg = 'Logging out user "%(username)s".' % \
        {'username': request.user.username}
    LOG.info(msg)
    endpoint = request.session.get('region_endpoint')

    # delete the project scoped token
    token = request.session.get('token')
    if token and endpoint:
        delete_token(endpoint=endpoint, token_id=token.id)

    # delete the domain scoped token if set
    domain_token = request.session.get('domain_token')
    if domain_token and endpoint:
        delete_token(endpoint=endpoint, token_id=domain_token.auth_token)

    """ Securely logs a user out. """
    return django_auth_views.logout_then_login(request, login_url=login_url,
                                               **kwargs)


def delete_token(endpoint, token_id):
    """Delete a token."""
    try:
        endpoint = utils.fix_auth_url_version(endpoint)

        session = utils.get_session()
        auth_plugin = token_endpoint.Token(endpoint=endpoint,
                                           token=token_id)
        client = utils.get_keystone_client().Client(session=session,
                                                    auth=auth_plugin)
        if utils.get_keystone_version() >= 3:
            client.tokens.revoke_token(token=token_id)
        else:
            client.tokens.delete(token=token_id)

        LOG.info('Deleted token %s' % token_id)
    except keystone_exceptions.ClientException:
        LOG.info('Could not delete token')


@login_required
def switch(request, tenant_id, redirect_field_name=auth.REDIRECT_FIELD_NAME):
    """Switches an authenticated user from one project to another."""
    LOG.debug('Switching to tenant %s for user "%s".'
              % (tenant_id, request.user.username))

    endpoint = utils.fix_auth_url_version(request.user.endpoint)
    session = utils.get_session()
    # Keystone can be configured to prevent exchanging a scoped token for
    # another token. Always use the unscoped token for requesting a
    # scoped token.
    unscoped_token = request.user.unscoped_token
    auth = utils.get_token_auth_plugin(auth_url=endpoint,
                                       token=unscoped_token,
                                       project_id=tenant_id)

    try:
        auth_ref = auth.get_access(session)
        msg = 'Project switch successful for user "%(username)s".' % \
            {'username': request.user.username}
        LOG.info(msg)
    except keystone_exceptions.ClientException:
        msg = (
            _('Project switch failed for user "%(username)s".') %
            {'username': request.user.username})
        messages.error(request, msg)
        auth_ref = None
        LOG.exception('An error occurred while switching sessions.')

    # Ensure the user-originating redirection url is safe.
    # Taken from django.contrib.auth.views.login()
    redirect_to = request.GET.get(redirect_field_name, '')
    if not is_safe_url(url=redirect_to, host=request.get_host()):
        redirect_to = settings.LOGIN_REDIRECT_URL

    if auth_ref:
        old_endpoint = request.session.get('region_endpoint')
        old_token = request.session.get('token')
        if old_token and old_endpoint and old_token.id != auth_ref.auth_token:
            delete_token(endpoint=old_endpoint, token_id=old_token.id)
        user = auth_user.create_user_from_token(
            request,
            auth_user.Token(auth_ref, unscoped_token=unscoped_token),
            endpoint)
        auth_user.set_session_from_user(request, user)
        message = (
            _('Switch to project "%(project_name)s" successful.') %
            {'project_name': request.user.project_name})
        messages.success(request, message)
    response = shortcuts.redirect(redirect_to)
    utils.set_response_cookie(response, 'recent_project',
                              request.user.project_id)
    return response


@login_required
def switch_region(request, region_name,
                  redirect_field_name=auth.REDIRECT_FIELD_NAME):
    """Switches the user's region for all services except Identity service.

    The region will be switched if the given region is one of the regions
    available for the scoped project. Otherwise the region is not switched.
    """
    if region_name in request.user.available_services_regions:
        request.session['services_region'] = region_name
        LOG.debug('Switching services region to %s for user "%s".'
                  % (region_name, request.user.username))

    redirect_to = request.GET.get(redirect_field_name, '')
    if not is_safe_url(url=redirect_to, host=request.get_host()):
        redirect_to = settings.LOGIN_REDIRECT_URL

    response = shortcuts.redirect(redirect_to)
    utils.set_response_cookie(response, 'services_region',
                              request.session['services_region'])
    return response
