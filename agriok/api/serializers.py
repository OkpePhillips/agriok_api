from rest_framework import serializers
from .models import (
    CustomUser,
    Insight,
    Product,
    Cart,
    CartItem,
    Order,
    OrderItem,
    Product,
    Farmland,
)
from django.contrib.auth import authenticate
from django.contrib.auth import password_validation
from django.utils.translation import gettext as _


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=8)

    class Meta:
        model = CustomUser
        fields = [
            "email",
            "first_name",
            "last_name",
            "city",
            "country",
            "phone_number",
            "postal_code",
            "password",
        ]

    def create(self, validated_data):
        user = CustomUser.objects.create_user(
            email=validated_data["email"],
            password=validated_data["password"],
            first_name=validated_data.get("first_name", ""),
            last_name=validated_data.get("last_name", ""),
            city=validated_data.get("city", ""),
            country=validated_data.get("country", ""),
            phone_number=validated_data.get("phone_number", ""),
            postal_code=validated_data.get("postal_code", ""),
        )
        return user


class EmailLoginSerializer(serializers.Serializer):
    email = serializers.EmailField()
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        user = authenticate(email=data["email"], password=data["password"])
        if not user:
            raise serializers.ValidationError("Invalid email or password.")
        if not user.is_active:
            raise serializers.ValidationError("User account is disabled.")
        return {"user": user}


class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            "id",
            "email",
            "first_name",
            "last_name",
            "city",
            "country",
            "phone_number",
            "postal_code",
            "is_active",
            "is_staff",
        ]


class UserUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = [
            "first_name",
            "last_name",
            "city",
            "country",
            "phone_number",
            "postal_code",
        ]


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        password_validation.validate_password(password=value)
        return value


class FarmInsightSerializer(serializers.ModelSerializer):
    class Meta:
        model = Insight
        fields = ["id", "title", "content", "date_posted", "user", "farmland"]
        read_only_fields = ["id", "date_posted", "user"]


class ProductSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product
        fields = "__all__"


class CartItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer()

    class Meta:
        model = CartItem
        fields = ["id", "product", "quantity"]


class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True, read_only=True)

    class Meta:
        model = Cart
        fields = ["id", "user", "created_at", "items"]


class OrderItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer()

    class Meta:
        model = OrderItem
        fields = ["id", "product", "quantity"]


class OrderSerializer(serializers.ModelSerializer):
    items = OrderItemSerializer(many=True, read_only=True)

    class Meta:
        model = Order
        fields = [
            "id",
            "user",
            "created_at",
            "status",
            "total_amount",
            "items",
        ]


class FarmlandSerializer(serializers.ModelSerializer):
    class Meta:
        model = Farmland
        fields = [
            "id",
            "sensors",
            "size",
            "location",
            "user",
        ]
        read_only_fields = ["user"]
