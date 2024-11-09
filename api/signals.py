from django.core.mail import EmailMultiAlternatives
from django.dispatch import receiver
from django.urls import reverse
from django_rest_passwordreset.signals import reset_password_token_created
from django.conf import settings
from rest_framework.reverse import reverse_lazy


@receiver(reset_password_token_created)
def password_reset_token_created(
    sender, instance, reset_password_token, *args, **kwargs
):
    reset_password_url = "{}?token={}".format(
        instance.request.build_absolute_uri(
            reverse_lazy("password_reset:reset-password-confirm")
        ),
        reset_password_token.key,
    )

    email_message = (
        f"Click the following link to reset your password: {reset_password_url}"
    )

    msg = EmailMultiAlternatives(
        "Reset Your Password",
        email_message,
        settings.DEFAULT_FROM_EMAIL,
        [reset_password_token.user.email],
    )
    print("Sending email to:", reset_password_token.user.email)
    msg.send()
    print("Email sent")
