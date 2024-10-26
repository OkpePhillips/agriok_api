from django.contrib import admin
from .models import Insight, Product, CustomUser


class ProductAdmin(admin.ModelAdmin):
    list_display = ("name", "price", "quantity")
    search_fields = ("name",)


class InsightAdmin(admin.ModelAdmin):
    list_display = ("title", "date_posted")
    search_fields = ("title",)


class UserAdmin(admin.ModelAdmin):
    list_display = (
        "id",
        "first_name",
        "last_name",
        "email",
        "city",
        "country",
        "phone_number",
        "postal_code",
    )
    search_fields = ("id",)


admin.site.register(Product, ProductAdmin)
admin.site.register(Insight, InsightAdmin)
admin.site.register(CustomUser, UserAdmin)
