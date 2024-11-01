from rest_framework import permissions


class IsOwnerOrAdmin(permissions.BasePermission):
    """
    Custom permission to allow only owners of a farmland or admin users to edit or delete.
    """

    def has_object_permission(self, request, view, obj):
        return obj.user == request.user or request.user.is_staff
