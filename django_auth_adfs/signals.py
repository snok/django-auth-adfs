from django.dispatch import Signal

post_authenticate = Signal(providing_args=["user", "claims", "adfs_response"])
