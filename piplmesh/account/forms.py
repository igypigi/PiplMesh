from django import forms
from django.forms.extras import widgets
from django.utils.translation import ugettext_lazy as _
from django.template import loader

from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.models import get_current_site

from piplmesh.account import fields, form_fields, models
from piplmesh.account.models import User

import base64

class UserUsernameForm(forms.Form):
    """
    Class with username form.
    """

    username = forms.RegexField(
        label=_("Username"),
        max_length=30,
        min_length=4,
        regex=r'^' + models.USERNAME_REGEX + r'$',
        help_text=_("Minimal of 4 characters and maximum of 30. Letters, digits and @/./+/-/_ only."),
        error_messages={
            'invalid': _("This value may contain only letters, numbers and @/./+/-/_ characters."),
        }
    )

    def clean_username(self):
        """
        This method checks whether the username exists in a case-insensitive manner.
        """

        username = self.cleaned_data['username']
        if models.User.objects(username__iexact=username).count():
            raise forms.ValidationError(_("A user with that username already exists."), code='username_exists')
        return username

class UserPasswordForm(forms.Form):
    """
    Class with user password form.
    """

    password1 = forms.CharField(
        label=_("Password"),
        min_length=6,
        widget=forms.PasswordInput,
    )
    password2 = forms.CharField(
        label=_("Password (repeat)"),
        widget=forms.PasswordInput,
        help_text=_("Enter the same password as above, for verification."),
    )

    def clean_password2(self):
        """
        This method checks whether the passwords match.
        """

        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password1 != password2:
            raise forms.ValidationError(_("The two password fields did not match."), code='password_mismatch')
        return password2

class UserCurrentPasswordForm(forms.Form):
    """
    Class with user current password form.
    """

    current_password = forms.CharField(
        label=_("Current password"),
        widget=forms.PasswordInput,
        help_text=_("Enter your current password, for verification."),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(UserCurrentPasswordForm, self).__init__(*args, **kwargs)

    def clean_current_password(self):
        """
        This method checks if user password is correct.
        """

        password = self.cleaned_data['current_password']
        if not self.user.check_password(password):
            raise forms.ValidationError(_("Your current password was incorrect."), code='password_incorrect')
        return password

class UserBasicInfoForm(forms.Form):
    """
    Class with user basic information form.
    """

    # TODO: Language field is missing?

    first_name = forms.CharField(label=_("First name"))
    last_name = forms.CharField(label=_("Last name"))
    email = forms.EmailField(label=_("E-mail"))
    gender = forms.ChoiceField(
        label=_("Gender"),
        choices=fields.GENDER_CHOICES,
        widget=forms.RadioSelect(),
    )
    birthdate = form_fields.LimitedDateTimeField(
        upper_limit=models.upper_birthdate_limit,
        lower_limit=models.lower_birthdate_limit,
        label=_("Birth date"),
        required=False,
        widget=widgets.SelectDateWidget(
            years=[
                y for y in range(
                    models.upper_birthdate_limit().year,
                    models.lower_birthdate_limit().year,
                    -1,
                )
            ],
        ),
    )

class UserAdditionalInfoForm(forms.Form):
    """
    Class with user additional information form.
    """

class RegistrationForm(UserUsernameForm, UserPasswordForm, UserBasicInfoForm):
    """
    Class with registration form.
    """

class AccountChangeForm(UserBasicInfoForm, UserAdditionalInfoForm, UserCurrentPasswordForm):
    """
    Class with form for changing your account settings.
    """

class PasswordChangeForm(UserCurrentPasswordForm, UserPasswordForm):
    """
    Class with form for changing password.
    """

class PasswordResetForm(forms.Form):
    error_messages = {
        'unknown': _("That e-mail address doesn't have an associated "
                     "user account. Are you sure you've registered?"),
        'unusable': _("The user account associated with this e-mail "
                      "address cannot reset the password."),
        }
    email = forms.EmailField(label=_("E-mail"), max_length=75)

    def clean_email(self):
        """
        Validates that an active user exists with the given email address.
        """
        email = self.cleaned_data["email"]
        self.users_cache = User.objects.filter(email__iexact=email,
            is_active=True)
        if not len(self.users_cache):
            raise forms.ValidationError(self.error_messages['unknown'])
        if any((not user.has_usable_password())
            for user in self.users_cache):
            raise forms.ValidationError(self.error_messages['unusable'])
        return email

    def save(self, domain_override=None,
             subject_template_name='registration/password_reset_subject.txt',
             email_template_name='registration/password_reset_email.html',
             use_https=False, token_generator=default_token_generator,
             from_email=None, request=None):
        """
        Generates a one-use only link for resetting password and sends to the
        user.
        """
        from django.core.mail import send_mail
        for user in self.users_cache:
            if not domain_override:
                current_site = get_current_site(request)
                site_name = current_site.name
                domain = current_site.domain
            else:
                site_name = domain = domain_override
            c = {
                'email': user.email,
                'domain': domain,
                'site_name': site_name,
                'uid': base64.b64encode(user.id.__str__()),
                'user': user,
                'token': token_generator.make_token(user),
                'protocol': use_https and 'https' or 'http',
                }
            subject = loader.render_to_string(subject_template_name, c)
            # Email subject *must not* contain newlines
            subject = ''.join(subject.splitlines())
            email = loader.render_to_string(email_template_name, c)
            send_mail(subject, email, from_email, [user.email])

class SetPasswordForm(forms.Form):
    """
    A form that lets a user change set his/her password without entering the
    old password
    """
    error_messages = {
        'password_mismatch': _("The two password fields didn't match."),
        }
    new_password1 = forms.CharField(label=_("New password"),
        widget=forms.PasswordInput)
    new_password2 = forms.CharField(label=_("New password confirmation"),
        widget=forms.PasswordInput)

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(SetPasswordForm, self).__init__(*args, **kwargs)

    def clean_new_password2(self):
        password1 = self.cleaned_data.get('new_password1')
        password2 = self.cleaned_data.get('new_password2')
        if password1 and password2:
            if password1 != password2:
                raise forms.ValidationError(
                    self.error_messages['password_mismatch'])
        return password2

    def save(self, commit=True):
        self.user.set_password(self.cleaned_data['new_password1'])
        if commit:
            self.user.save()
        return self.user

class EmailConfirmationSendTokenForm(forms.Form):
    """
    Form for sending an e-mail address confirmation token.
    """

class EmailConfirmationProcessTokenForm(forms.Form):
    """
    Form for processing an e-mail address confirmation token.
    """

    confirmation_token = forms.CharField(
        label=_("Confirmation token"),
        min_length=20,
        max_length=20,
        required=True,
        help_text=_("Please enter the confirmation token you received to your e-mail address."),
    )

    def __init__(self, user, *args, **kwargs):
        self.user = user
        super(EmailConfirmationProcessTokenForm, self).__init__(*args, **kwargs)

    def clean_confirmation_token(self):
        """
        This method checks if user confirmation token is correct.
        """

        confirmation_token = self.cleaned_data['confirmation_token']
        if not self.user.email_confirmation_token.check_token(confirmation_token):
            raise forms.ValidationError(_("The confirmation token is invalid or has expired. Please retry."), code='confirmation_token_incorrect')
        return confirmation_token
