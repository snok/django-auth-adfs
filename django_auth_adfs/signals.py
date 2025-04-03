from django.dispatch import Signal

# Arguments sent with the signal:
# * user
# * claims
# * adfs_response
post_authenticate = Signal()

# Arguments sent with the signal:
# * request
# * claims
adfs_claims_processed = Signal()