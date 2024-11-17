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
    Transaction,
    TrendingPost,
    ClientCertificate,
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
            "isAdmin",
            "photo",
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
            "photo",
        ]


class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True)

    def validate_new_password(self, value):
        password_validation.validate_password(password=value)
        return value


class FarmInsightSerializer(serializers.ModelSerializer):
    user_id = serializers.PrimaryKeyRelatedField(
        queryset=CustomUser.objects.all(), source="user"
    )

    class Meta:
        model = Insight
        fields = ["id", "title", "content", "date_posted", "user_id", "farmland"]
        read_only_fields = ["id", "date_posted"]


class ProductSerializer(serializers.ModelSerializer):
    photo = serializers.ImageField(required=False)

    class Meta:
        model = Product
        fields = "__all__"


class AddToCartSerializer(serializers.Serializer):
    product_id = serializers.IntegerField()
    quantity = serializers.IntegerField(min_value=1)

    def validate_product_id(self, value):
        # Check if the product exists
        if not Product.objects.filter(id=value).exists():
            raise serializers.ValidationError("Product does not exist.")
        return value

    def validate_quantity(self, value):
        if value < 1:
            raise serializers.ValidationError("Quantity must be at least 1.")
        return value


class CartItemSerializer(serializers.ModelSerializer):
    product = ProductSerializer(read_only=True)

    class Meta:
        model = CartItem
        fields = ["id", "product", "quantity"]


class CartItemUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = CartItem
        fields = ["quantity"]


class CartSerializer(serializers.ModelSerializer):
    items = CartItemSerializer(many=True)

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


class TransactionSerializer(serializers.ModelSerializer):
    class Meta:
        model = Transaction
        fields = [
            "id",
            "user",
            "items",
            "amount",
            "description",
            "created_at",
            "updated_at",
        ]
        read_only_fields = ["user", "created_at", "updated_at"]


class UserPostSerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomUser
        fields = ["id", "first_name", "photo"]


class PostSerializer(serializers.ModelSerializer):
    user = UserPostSerializer(read_only=True)

    class Meta:
        model = TrendingPost
        fields = ["id", "title", "content", "user", "image", "created_at", "updated_at"]
        read_only_fields = ["user", "created_at", "updated_at"]


class MTNMomoPaymentSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    phone_number = serializers.CharField(max_length=15)
    tx_ref = serializers.CharField(max_length=100)
    currency = serializers.CharField(max_length=3, default="RWF")
    order_id = serializers.IntegerField()


class ClientCertificateSerializer(serializers.Serializer):
    common_name = serializers.CharField(max_length=255)
    country_name = serializers.CharField(max_length=2)
    organization_name = serializers.CharField(max_length=255)


class ClientCertificateDetailSerializer(serializers.ModelSerializer):
    class Meta:
        model = ClientCertificate
        fields = ["common_name", "certificate", "private_key", "created_at"]


class MomoPaymentSerializer(serializers.Serializer):
    amount = serializers.DecimalField(max_digits=10, decimal_places=2)
    currency = serializers.ChoiceField(choices=["RWF", "EUR"])
    external_id = serializers.CharField(max_length=100)
    payer_party_id = serializers.RegexField(
        regex=r"^\d+$",
        max_length=12,
        min_length=10,
        error_messages={"invalid": "Enter a valid phone number."},
    )
    payer_message = serializers.CharField(
        max_length=255, required=False, allow_blank=True
    )
    payee_note = serializers.CharField(max_length=255, required=False, allow_blank=True)
