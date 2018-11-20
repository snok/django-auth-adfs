from django.dispatch import Signal

adfs_backend_post_authenticate = Signal(
    providing_args=["user", "claims", "json_response"])
