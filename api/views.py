from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from django.conf import settings
from rest_framework.permissions import (
    IsAuthenticated,
    IsAdminUser,
    AllowAny,
    IsAuthenticatedOrReadOnly,
)
from rest_framework_simplejwt.tokens import RefreshToken
from .models import (
    Product,
    Insight,
    CustomUser,
    Cart,
    CartItem,
    Order,
    OrderItem,
    Farmland,
    Transaction,
    TrendingPost,
    Payment,
    ClientCertificate,
)
from .serializers import (
    RegisterSerializer,
    UserProfileSerializer,
    UserUpdateSerializer,
    ChangePasswordSerializer,
    EmailLoginSerializer,
    FarmInsightSerializer,
    ProductSerializer,
    CartSerializer,
    OrderSerializer,
    FarmlandSerializer,
    TransactionSerializer,
    PostSerializer,
    AddToCartSerializer,
    MTNMomoPaymentSerializer,
    CartItemSerializer,
    CartItemUpdateSerializer,
    ClientCertificateSerializer,
    ClientCertificateDetailSerializer,
)
from .permissions import IsOwnerOrAdmin
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.http import JsonResponse
from rave_python import Rave, RaveExceptions
from django.core.cache import cache
from src.certificates import Subject, CertificateAuthority, ClientCertificateGenerator
import os

rave = Rave(
    "FLWPUBK_TEST-4d92baacb8c49aff4800ccefaae2a862-X",
    "FLWSECK_TEST-7a5406d0c7a68c9b9e08d9b4ee06c27d-X",
    usingEnv=False,
)


class RegisterView(APIView):
    """
    View to register a new user.
    """

    @swagger_auto_schema(
        operation_summary="Register a new user",
        operation_description="This endpoint allows a new user to register by providing a first_name, last_name, username, email, and password.",
        tags=["User Processes"],
        request_body=RegisterSerializer,
        responses={
            201: openapi.Response(
                description="Successfully registered user details",
                examples={
                    "application/json": {"message": "User registered successfully."}
                },
            ),
            400: openapi.Response(
                description="Bad Request - validation errors",
                examples={
                    "application/json": {
                        "username": ["This field is required."],
                        "email": ["This field is required."],
                        "password": ["This field is required."],
                    }
                },
            ),
        },
    )
    def post(self, request):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "User registered successfully."},
                status=status.HTTP_201_CREATED,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class EmailLoginView(APIView):
    """
    View for user email login.
    """

    @swagger_auto_schema(
        operation_summary="User Login",
        operation_description="This endpoint allows a user to login using their email and password.",
        tags=["User Processes"],
        request_body=EmailLoginSerializer,
        responses={
            201: openapi.Response(
                description="Login successful, returns user ID",
                examples={"application/json": {"user_id": 1}},
            ),
            400: openapi.Response(
                description="Bad Request - validation errors",
                examples={
                    "application/json": {
                        "non_field_errors": [
                            "Unable to log in with provided credentials."
                        ]
                    }
                },
            ),
        },
    )
    def post(self, request):
        serializer = EmailLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            refresh = RefreshToken.for_user(user)
            response = Response(
                {
                    "user_id": user.id,
                    "first_name": user.first_name,
                    "access_token": str(refresh.access_token),
                    "isAdmin": user.isAdmin,
                },
                status=status.HTTP_201_CREATED,
            )

            # Set the access token in the cookie
            response.set_cookie(
                key="access_token",
                value=str(refresh.access_token),
                httponly=True,
                secure=True,
            )
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutView(APIView):
    """
    View for user logout.
    """

    @swagger_auto_schema(
        operation_summary="User Logout",
        operation_description="This endpoint logs out a user by clearing the access token.",
        tags=["User Processes"],
        responses={
            200: openapi.Response(
                description="Logout successful",
                examples={"application/json": {"detail": "Logout successful"}},
            ),
        },
    )
    def post(self, request):
        access_token_str = request.COOKIES.get("access_token") or request.data.get(
            "access_token"
        )

        try:
            refresh_token = RefreshToken(access_token_str)
            refresh_token.blacklist()

            response = Response(
                {"detail": "Logout successful."}, status=status.HTTP_200_OK
            )
            response.delete_cookie("access_token")
            return response

        except Exception as e:
            return Response({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class ProfileView(APIView):
    """
    View to get the profile of the authenticated user.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get user profile",
        operation_description="This endpoint allows authenticated users to retrieve their profile information.",
        tags=["User Processes"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="User profile details", schema=UserProfileSerializer
            ),
            401: "Unauthorized",
        },
    )
    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UpdateProfileView(APIView):
    """
    View to update the authenticated user's profile.
    """

    permission_classes = [IsAuthenticated]
    parser_classes = (FormParser, MultiPartParser)

    @swagger_auto_schema(
        operation_summary="Update user profile",
        operation_description="This endpoint allows authenticated users to update their profile information.",
        tags=["User Processes"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=UserUpdateSerializer,
        responses={
            200: openapi.Response(
                description="Profile updated successfully", schema=UserProfileSerializer
            ),
            400: openapi.Response(description="Bad Request - validation errors"),
            401: "Unauthorized",
        },
    )
    def put(self, request):
        user = request.user
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    """
    View to change the authenticated user's password.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Change password",
        operation_description="This endpoint allows authenticated users to change their password.",
        tags=["User Processes"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=ChangePasswordSerializer,
        responses={
            200: openapi.Response(description="Password changed successfully"),
            400: openapi.Response(
                description="Bad Request - validation errors or wrong old password"
            ),
            401: "Unauthorized",
        },
    )
    def post(self, request):
        user = request.user
        serializer = ChangePasswordSerializer(data=request.data)

        if serializer.is_valid():
            old_password = serializer.validated_data["old_password"]
            new_password = serializer.validated_data["new_password"]

            if not user.check_password(old_password):
                return Response(("Wrong password"), status=status.HTTP_400_BAD_REQUEST)

            user.set_password(new_password)
            user.save()

            update_session_auth_hash(request, user)

            return Response(
                ("Password changed successfully"), status=status.HTTP_200_OK
            )

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FarmInsightAPIView(APIView):
    """
    View to get and create farm insights.
    """

    def get_permissions(self):
        if self.request.method == "GET":
            return [IsAuthenticated()]
        return [IsAdminUser()]

    @swagger_auto_schema(
        operation_summary="Get farm insights",
        operation_description="This endpoint allows authenticated users to retrieve their farm insights.",
        tags=["Insights"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="List of farm insights",
                schema=FarmInsightSerializer(many=True),
            ),
            401: "Unauthorized",
        },
    )
    def get(self, request):
        insights = Insight.objects.filter(user=request.user)
        serializer = FarmInsightSerializer(insights, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Create farm insight",
        operation_description="This endpoint allows an admin to create a new farm insight.",
        tags=["Insights"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=FarmInsightSerializer,
        responses={
            201: openapi.Response(
                description="Farm insight created successfully",
                schema=FarmInsightSerializer,
            ),
            400: openapi.Response(description="Bad Request - validation errors"),
            404: openapi.Response(description="User not found"),
            401: "Unauthorized",
        },
    )
    def post(self, request):
        user_id = request.data.get("user_id")
        try:
            user = CustomUser.objects.get(id=user_id)
        except CustomUser.DoesNotExist:
            return Response(
                {"detail": "The specified user does not exist."},
                status=status.HTTP_404_NOT_FOUND,
            )
        serializer = FarmInsightSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FarmInsightDetailAPIView(APIView):
    """
    View to retrieve, update and delete specific farm insights.
    """

    def get_permissions(self):
        if self.request.method == "GET":
            return [IsAuthenticated()]
        return [IsAdminUser()]

    @swagger_auto_schema(
        operation_summary="Get specific farm insight",
        operation_description="This endpoint allows users to retrieve a specific farm insight by its ID.",
        tags=["Insights"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="Farm insight details", schema=FarmInsightSerializer
            ),
            404: openapi.Response(description="Farm insight not found"),
        },
    )
    def get_object(self, pk):
        try:
            return Insight.objects.get(pk=pk)
        except Insight.DoesNotExist:
            return None

    def get(self, request, pk):
        insight = self.get_object(pk)
        if insight is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = FarmInsightSerializer(insight)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Update specific farm insight",
        operation_description="This endpoint allows an admin to update a specific farm insight by its ID.",
        tags=["Insights"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=FarmInsightSerializer,
        responses={
            200: openapi.Response(
                description="Farm insight updated successfully",
                schema=FarmInsightSerializer,
            ),
            404: openapi.Response(description="Farm insight not found"),
            400: openapi.Response(description="Bad Request - validation errors"),
        },
    )
    def put(self, request, pk):
        insight = self.get_object(pk)
        if insight is None:
            return Response(status=status.HTTP_404_NOT_FOUND)

        data = request.data.copy()
        data.pop("user", None)
        serializer = FarmInsightSerializer(insight, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Delete specific farm insight",
        operation_description="This endpoint allows an admin to delete a specific farm insight by its ID.",
        tags=["Insights"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            204: openapi.Response(description="Farm insight deleted successfully"),
            404: openapi.Response(description="Farm insight not found"),
        },
    )
    def delete(self, request, pk):
        insight = self.get_object(pk)
        if insight is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        insight.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ProductAPIView(APIView):
    """
    View to get and create products.
    """

    permission_classes = [IsAdminUser]
    parser_classes = (FormParser, MultiPartParser)

    @swagger_auto_schema(
        operation_summary="Create product",
        operation_description="This endpoint allows an admin to create a new product.",
        tags=["Products"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                "photo",
                openapi.IN_FORM,
                description="Product image",
                type=openapi.TYPE_FILE,
                required=True,
            ),
        ],
        request_body=ProductSerializer,
        responses={
            201: openapi.Response(
                description="Product created successfully", schema=ProductSerializer
            ),
            400: openapi.Response(description="Bad Request - validation errors"),
            401: "Unauthorized",
        },
    )
    def post(self, request):
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductDetailAPIView(APIView):
    """
    View to retrieve, update and delete specific products.
    """

    parser_classes = (FormParser, MultiPartParser)

    def get_permissions(self):
        if self.request.method == "GET":
            return [AllowAny()]
        return [IsAdminUser()]

    def get_object(self, pk):
        try:
            return Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return None

    @swagger_auto_schema(
        operation_summary="Get specific product",
        operation_description="This endpoint allows users to retrieve a specific product by its ID.",
        tags=["Products"],
        responses={
            200: openapi.Response(
                description="Product details", schema=ProductSerializer
            ),
            404: openapi.Response(description="Product not found"),
        },
    )
    def get(self, request, pk):
        product = self.get_object(pk)
        if product is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = ProductSerializer(product)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Edit product",
        operation_description="This endpoint allows an admin to edit a product.",
        tags=["Products"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            ),
            openapi.Parameter(
                "photo",
                openapi.IN_FORM,
                description="Product image",
                type=openapi.TYPE_FILE,
                required=True,
            ),
        ],
        request_body=ProductSerializer,
        responses={
            201: openapi.Response(
                description="Product created successfully", schema=ProductSerializer
            ),
            400: openapi.Response(description="Bad Request - validation errors"),
            401: "Unauthorized",
        },
    )
    def put(self, request, pk):
        product = self.get_object(pk)
        if product is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = ProductSerializer(product, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Delete specific product",
        operation_description="This endpoint allows an admin to delete a specific product by its ID.",
        tags=["Products"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            ),
        ],
        responses={
            204: openapi.Response(description="Product deleted successfully"),
            404: openapi.Response(description="Product not found"),
        },
    )
    def delete(self, request, pk):
        product = self.get_object(pk)
        if product is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        product.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AddToCartView(APIView):
    """This endpoint allows users to add a product to their cart"""

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Add item to cart",
        operation_description="This endpoint allows users to add a product to their cart.",
        tags=["Cart"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=AddToCartSerializer,
        responses={
            201: openapi.Response(
                description="Item added to cart successfully", schema=CartSerializer
            ),
            400: openapi.Response(description="Bad Request - validation errors"),
            401: "Unauthorized",
        },
    )
    def post(self, request):
        product_id = request.data.get("product_id")
        quantity = request.data.get("quantity", 1)

        product = get_object_or_404(Product, id=product_id)

        cart, _ = Cart.objects.get_or_create(user=request.user)

        cart_item, created = CartItem.objects.get_or_create(
            cart=cart, product=product, defaults={"quantity": quantity}
        )

        if not created:
            cart_item.quantity += quantity
            cart_item.save()

        return Response(
            {"detail": "Product added to cart"}, status=status.HTTP_201_CREATED
        )


class CartDetailAPIView(APIView):
    """
    View to retrieve, update and delete specific cart by id.
    """

    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return CartItem.objects.get(pk=pk)
        except CartItem.DoesNotExist:
            return None

    @swagger_auto_schema(
        operation_summary="Get specific cart item",
        operation_description="This endpoint allows users to retrieve a specific cart by its ID.",
        tags=["Cart"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="Cart item details", schema=CartSerializer
            ),
            404: openapi.Response(description="Cart item not found"),
        },
    )
    def get(self, request, pk):
        cart_item = self.get_object(pk)
        if cart_item is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = CartItemSerializer(cart_item)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Update specific cart item",
        operation_description="This endpoint allows users to update a specific cart by its ID.",
        tags=["Cart"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=CartItemUpdateSerializer,
        responses={
            200: openapi.Response(
                description="Cart item updated successfully",
                schema=CartItemUpdateSerializer,
            ),
            404: openapi.Response(description="Cart item not found"),
            400: openapi.Response(description="Bad Request - validation errors"),
        },
    )
    def put(self, request, pk):
        cart_item = self.get_object(pk)
        if cart_item is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = CartItemSerializer(cart_item, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Delete specific cart item",
        operation_description="This endpoint allows users to delete a specific cart by its ID.",
        tags=["Cart"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            204: openapi.Response(description="Cart item deleted successfully"),
            404: openapi.Response(description="Cart item not found"),
        },
    )
    def delete(self, request, pk):
        cart_item = self.get_object(pk)
        if cart_item is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        cart_item.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class CartsAPIView(APIView):
    """
    View to retrieve, update and clear carts.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get all cart items for logged-in user",
        operation_description="This endpoint retrieves all cart items for the logged-in user.",
        tags=["Cart"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="List of cart items for the user",
                schema=CartSerializer(many=True),
            ),
            401: openapi.Response(description="Unauthorized - user not logged in"),
        },
    )
    def get(self, request):
        cart_items = Cart.objects.filter(user=request.user)

        if not cart_items.exists():
            return Response(
                {"detail": "No cart items found for this user"},
                status=status.HTTP_404_NOT_FOUND,
            )

        serializer = CartSerializer(cart_items, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Clear cart for logged-in user",
        operation_description="This endpoint clears the cart of the logged-in user.",
        tags=["Cart"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="Clear cart of the logged in user",
                schema=CartSerializer(many=True),
            ),
            401: openapi.Response(description="Unauthorized - user not logged in"),
        },
    )
    def delete(self, request):
        user_cart = Cart.objects.filter(user=request.user)

        if user_cart.exists():
            user_cart.delete()
            return Response(
                {"message": "Cart cleared successfully."},
                status=status.HTTP_204_NO_CONTENT,
            )
        return Response(
            {"message": "Your cart is empty."}, status=status.HTTP_404_NOT_FOUND
        )


class PlaceOrderView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Place an order",
        operation_description="This endpoint allows a user to place an order based on the items in their cart.",
        tags=["Orders"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            201: openapi.Response(description="Order placed successfully"),
            400: openapi.Response(description="Bad Request - Cart is empty"),
            401: "Unauthorized",
        },
    )
    def post(self, request):
        cart = get_object_or_404(Cart, user=request.user)
        if not cart.items.exists():
            return Response(
                {"detail": "Cart is empty"}, status=status.HTTP_400_BAD_REQUEST
            )

        total_amount = sum(
            item.product.price * item.quantity for item in cart.items.all()
        )

        order = Order.objects.create(user=request.user, total_amount=total_amount)

        for item in cart.items.all():
            OrderItem.objects.create(
                order=order, product=item.product, quantity=item.quantity
            )
            # Reduce the quantity of Products by the quantity ordered
            item.product.quantity -= item.quantity
            item.product.save()

        # Clear cart after placing order
        cart.items.all().delete()

        return Response(
            {"detail": "Order placed successfully", "order_id": order.id},
            status=status.HTTP_201_CREATED,
        )


class OrderHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Retrieve order history",
        operation_description="This endpoint allows a user to retrieve their order history.",
        tags=["Orders"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="List of orders", schema=OrderSerializer(many=True)
            ),
            401: "Unauthorized",
        },
    )
    def get(self, request):
        orders = Order.objects.filter(user=request.user)
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)


class AllOrdersView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Retrieves all orders by an Admin",
        operation_description="This endpoint allows an admin user to retrieve all orders.",
        tags=["Orders"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="List of orders", schema=OrderSerializer(many=True)
            ),
            401: "Unauthorized",
        },
    )
    def get(self, request):
        orders = Order.objects.all()
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)


class UserAPIView(APIView):

    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_summary="Retrieve users",
        operation_description="This endpoint allows an admin to retrieve all users or a specific user by ID.",
        tags=["Admin Processes"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="Admin Processes", schema=UserProfileSerializer(many=True)
            ),
            404: openapi.Response(description="User not found"),
        },
    )
    def get(self, request, pk=None):
        """Admin Processes to retrieve all users"""
        if pk:
            user = get_object_or_404(CustomUser, pk=pk)
            serializer = UserProfileSerializer(user)
        else:
            users = CustomUser.objects.all()
            serializer = UserProfileSerializer(users, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Delete a user",
        tags=["Admin Processes"],
        operation_description="This endpoint allows an admin to delete a specific user by ID.",
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            204: openapi.Response(description="User deleted successfully"),
            404: openapi.Response(description="User not found"),
        },
    )
    def delete(self, request, pk):
        """Admin Process to delete a specific user"""
        user = get_object_or_404(CustomUser, pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class FarmlandAPIView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Retrieve user's farmlands",
        operation_description="This endpoint allows users to retrieve their farmlands.",
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="List of farmlands", schema=FarmlandSerializer(many=True)
            ),
            401: "Unauthorized",
        },
    )
    def get(self, request):
        farmlands = Farmland.objects.filter(user=request.user)
        serializer = FarmlandSerializer(farmlands, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Create farmland",
        operation_description="This endpoint allows users to create a new farmland.",
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=FarmlandSerializer,
        responses={
            201: openapi.Response(
                description="Farmland created successfully", schema=FarmlandSerializer
            ),
            400: openapi.Response(description="Bad Request - validation errors"),
            401: "Unauthorized",
        },
    )
    def post(self, request):
        user = request.user
        serializer = FarmlandSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class FarmlandDetailAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOwnerOrAdmin]

    def get_object(self, pk):
        try:
            return Farmland.objects.get(pk=pk)
        except Farmland.DoesNotExist:
            return None

    @swagger_auto_schema(
        operation_summary="Retrieve specific farmland",
        operation_description="This endpoint allows users to retrieve a specific farmland by its ID.",
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="Farmland details", schema=FarmlandSerializer
            ),
            404: openapi.Response(description="Farmland not found"),
        },
    )
    def get(self, request, pk):
        farmland = self.get_object(pk)
        if farmland is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = FarmlandSerializer(farmland)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Update specific farmland",
        operation_description="This endpoint allows users to update a specific farmland by its ID.",
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=FarmlandSerializer,
        responses={
            200: openapi.Response(
                description="Farmland updated successfully", schema=FarmlandSerializer
            ),
            404: openapi.Response(description="Farmland not found"),
            400: openapi.Response(description="Bad Request - validation errors"),
        },
    )
    def put(self, request, pk):
        farmland = self.get_object(pk)
        if farmland is None:
            return Response(status=status.HTTP_404_NOT_FOUND)

        self.check_object_permissions(request, farmland)
        data = request.data.copy()
        data.pop("user", None)
        serializer = FarmlandSerializer(farmland, data=data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Delete specific farmland",
        operation_description="This endpoint allows users to delete a specific farmland by its ID.",
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            204: openapi.Response(description="Farmland deleted successfully"),
            404: openapi.Response(description="Farmland not found"),
        },
    )
    def delete(self, request, pk):
        farmland = self.get_object(pk)
        if farmland is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        self.check_object_permissions(request, farmland)
        farmland.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class TransactionView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Create a transaction",
        operation_description="This endpoint allows users to create a new transaction.",
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=TransactionSerializer,
        responses={
            201: openapi.Response(
                description="Transaction created successfully",
                schema=TransactionSerializer,
            ),
            400: openapi.Response(description="Bad Request - validation errors"),
            401: "Unauthorized",
        },
    )
    def post(self, request):
        serializer = TransactionSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user, transaction_type="manual")
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Retrieve transactions",
        operation_description="This endpoint allows users to retrieve their transactions or a specific transaction by ID.",
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="List of transactions or transaction details",
                schema=TransactionSerializer(many=True),
            ),
            404: openapi.Response(description="Transaction not found"),
            401: "Unauthorized",
        },
    )
    def get(self, request, pk=None):
        """Retrieve a specific transaction or list all transactions for the user"""
        if pk:
            transaction = get_object_or_404(Transaction, pk=pk, user=request.user)
            serializer = TransactionSerializer(transaction)
            return Response(serializer.data)
        else:
            transactions = Transaction.objects.filter(user=request.user)
            serializer = TransactionSerializer(transactions, many=True)
            return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Update an existing transaction",
        operation_description="This endpoint allows users to update a specific transaction by ID.",
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=TransactionSerializer,
        responses={
            200: openapi.Response(
                description="Transaction updated successfully",
                schema=TransactionSerializer,
            ),
            404: openapi.Response(description="Transaction not found"),
            400: openapi.Response(description="Bad Request - validation errors"),
            401: "Unauthorized",
        },
    )
    def put(self, request, pk):
        """Update an existing transaction"""
        transaction = get_object_or_404(Transaction, pk=pk, user=request.user)
        serializer = TransactionSerializer(transaction, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Delete a transaction",
        operation_description="This endpoint allows users to delete a specific transaction by its ID.",
        responses={
            204: openapi.Response(description="Post deleted successfully"),
            404: openapi.Response(description="Post not found"),
            401: "Unauthorized",
        },
    )
    def delete(self, request, pk):
        """Delete an existing transaction"""
        transaction = get_object_or_404(Transaction, pk=pk, user=request.user)
        transaction.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class PostView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]
    parser_classes = (FormParser, MultiPartParser)

    @swagger_auto_schema(
        operation_summary="List all posts",
        operation_description="This endpoint allows users to retrieve all posts.",
        tags=["Trending Posts"],
        responses={
            200: openapi.Response(
                description="List of posts", schema=PostSerializer(many=True)
            ),
            401: "Unauthorized",
        },
    )
    def get(self, request):
        """List all posts"""
        posts = TrendingPost.objects.all()
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Create a new post",
        operation_description="This endpoint allows users to create a new post.",
        tags=["Trending Posts"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=PostSerializer,
        responses={
            201: openapi.Response(
                description="Post created successfully", schema=PostSerializer
            ),
            400: openapi.Response(description="Bad Request - validation errors"),
            401: "Unauthorized",
        },
    )
    def post(self, request):
        """Create a new post"""
        if not request.user.is_authenticated:
            return Response(
                {"detail": "Authentication credentials were not provided."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PostDetailView(APIView):
    permission_classes = [IsAuthenticatedOrReadOnly]
    parser_classes = (FormParser, MultiPartParser)

    def get_object(self, pk, user):
        return get_object_or_404(TrendingPost, pk=pk, user=user)

    @swagger_auto_schema(
        operation_summary="Retrieve a specific post",
        operation_description="This endpoint allows users to retrieve a specific post by its ID.",
        tags=["Trending Posts"],
        responses={
            200: openapi.Response(description="Post details", schema=PostSerializer),
            404: openapi.Response(description="Post not found"),
            401: "Unauthorized",
        },
    )
    def get(self, request, pk):
        """Retrieve a specific post"""
        post = get_object_or_404(TrendingPost, pk=pk)
        serializer = PostSerializer(post)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Update an existing post",
        operation_description="This endpoint allows users to update a specific post by its ID.",
        tags=["Trending Posts"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=PostSerializer,
        responses={
            200: openapi.Response(
                description="Post updated successfully", schema=PostSerializer
            ),
            404: openapi.Response(description="Post not found"),
            400: openapi.Response(description="Bad Request - validation errors"),
            401: "Unauthorized",
        },
    )
    def put(self, request, pk):
        """Update an existing post"""
        if not request.user.is_authenticated:
            return Response(
                {"detail": "Authentication credentials were not provided."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        post = self.get_object(pk, request.user)
        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Delete a post",
        operation_description="This endpoint allows users to delete a specific post by its ID.",
        tags=["Trending Posts"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            204: openapi.Response(description="Post deleted successfully"),
            404: openapi.Response(description="Post not found"),
            401: "Unauthorized",
        },
    )
    def delete(self, request, pk):
        """Delete a post"""
        if not request.user.is_authenticated:
            return Response(
                {"detail": "Authentication credentials were not provided."},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        post = self.get_object(pk, request.user)
        post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class UserPostView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="List all posts of the authenticated user",
        operation_description="This endpoint allows users to retrieve all posts.",
        tags=["Trending Posts"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="List of posts", schema=PostSerializer(many=True)
            ),
            401: "Unauthorized",
        },
    )
    def get(self, request):
        """List the posts of an authenticated user"""
        posts = TrendingPost.objects.filter(user=request.user)
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)


class UserSpecificPost(APIView):
    """Retrieve a specific post of the logged in user"""

    @swagger_auto_schema(
        operation_summary="Retrieve a specific post of a specific user",
        operation_description="This endpoint allows users to retrieve a post that they made.",
        tags=["Trending Posts"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(
                description="List of posts", schema=PostSerializer(many=True)
            ),
            401: "Unauthorized",
        },
    )
    def get(self, request, pk):
        """Retrieve a specific post of a specific user"""
        post = get_object_or_404(TrendingPost, pk=pk, user=request.user)
        serializer = PostSerializer(post)
        return Response(serializer.data)


class MTNMomoPaymentView(APIView):
    """
    View to handle payments via MTN MoMo.
    """

    @swagger_auto_schema(
        operation_summary="Make payment with MTN MOMO RWANDA",
        operation_description="This endpoint allows users to make payment for orders with MTN MOMO.",
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=MTNMomoPaymentSerializer,
        responses={
            200: openapi.Response(
                description="Post updated successfully", schema=PostSerializer
            ),
            404: openapi.Response(description="Post not found"),
            400: openapi.Response(description="Bad Request - validation errors"),
            401: "Unauthorized",
        },
    )
    def post(self, request):
        serializer = MTNMomoPaymentSerializer(data=request.data)
        if serializer.is_valid():
            amount = serializer.validated_data["amount"]
            phone_number = serializer.validated_data["phone_number"]
            tx_ref = serializer.validated_data["tx_ref"]
            currency = serializer.validated_data["currency"]
            order_id = serializer.validated_data["order_id"]

            try:
                # Retrieve the order
                order = Order.objects.get(id=order_id)

                # Create a Payment record
                payment = Payment.objects.create(
                    order=order,
                    tx_ref=tx_ref,
                    amount=amount,
                    status="Pending",
                )
                print("Payment created successfully:", payment)
                # Charge the mobile money payment
                response = rave.MobileMoney.charge(
                    {
                        "txRef": tx_ref,
                        "amount": amount,
                        "currency": currency,
                        "payment_type": "mobilemoneyrwanda",
                        "phonenumber": phone_number,
                        "redirect_url": "https://agri-ok.vercel.app/",  # Redirect after payment
                    }
                )
                print(response)
                # Update payment and order status if transaction is complete
                if response.get("transactionComplete"):
                    payment.complete_payment()
                    return JsonResponse(
                        {"message": "Payment successful! Order status updated."},
                        status=status.HTTP_201_CREATED,
                    )
                else:
                    return JsonResponse(
                        {"message": "Transaction is pending."},
                        status=status.HTTP_202_ACCEPTED,
                    )

            except Order.DoesNotExist:
                return JsonResponse(
                    {"error": "Order not found."},
                    status=status.HTTP_404_NOT_FOUND,
                )
            except RaveExceptions.TransactionChargeError as e:
                return JsonResponse(
                    {"error": str(e)}, status=status.HTTP_400_BAD_REQUEST
                )
            except Exception as e:
                return JsonResponse(
                    {"error": "An error occurred."},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
        return JsonResponse(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class VerifyPaymentView(APIView):
    def post(self, request):
        tx_ref = request.data.get("tx_ref")

        if not tx_ref:
            return JsonResponse(
                {"error": "tx_ref is required."}, status=status.HTTP_400_BAD_REQUEST
            )

        try:
            response = rave.Transaction.verify(tx_ref)
            if response.get("transactionComplete"):
                return JsonResponse(
                    {"message": "Transaction verified!"}, status=status.HTTP_200_OK
                )
            else:
                return JsonResponse(
                    {"message": "Transaction not complete."},
                    status=status.HTTP_202_ACCEPTED,
                )

        except RaveExceptions.TransactionVerificationError as e:
            return JsonResponse({"error": str(e)}, status=status.HTTP_400_BAD_REQUEST)


class GetProductView(APIView):
    """Retrieve all products. Authentication not needed"""

    @swagger_auto_schema(
        operation_summary="Retieve all products from database",
        operation_description="This endpoint allows users to retrieve a list of products.",
        tags=["Products"],
        responses={
            200: openapi.Response(
                description="List of products", schema=ProductSerializer(many=True)
            )
        },
    )
    def get(self, request):
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)


class OrderDetailAPIView(APIView):
    """
    View to retrieve and delete specific order by id.
    """

    permission_classes = [IsAuthenticated]

    def get_object(self, pk):
        try:
            return Order.objects.get(pk=pk)
        except Order.DoesNotExist:
            return None

    @swagger_auto_schema(
        operation_summary="Get a specific order",
        operation_description="This endpoint allows users to retrieve a specific order by its ID.",
        tags=["Orders"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            200: openapi.Response(description="Order details", schema=OrderSerializer),
            404: openapi.Response(description="Cart item not found"),
        },
    )
    def get(self, request, pk):
        order = self.get_object(pk)
        if order is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = OrderSerializer(order)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Delete specific order by id",
        operation_description="This endpoint allows users to delete a specific order by its ID.",
        tags=["Orders"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            204: openapi.Response(description="Order deleted successfully"),
            404: openapi.Response(description="Order not found"),
        },
    )
    def delete(self, request, pk):
        order = self.get_object(pk)
        if order is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        order.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ClientCertificateView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Create a client certificate for MQTT connection",
        operation_description="This endpoint creates and returns a signed certificate for MQTT clients to connect to the MQTT server.",
        tags=["Certificates"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=ClientCertificateSerializer,
        responses={
            201: openapi.Response(
                description=" Certificate created successfully",
                schema=ClientCertificateDetailSerializer,
            ),
            401: openapi.Response(description="Unauthorized"),
        },
    )
    def post(self, request):
        serializer = ClientCertificateSerializer(data=request.data)
        if serializer.is_valid():
            user = request.user
            validated_data = serializer.validated_data

            # Define the client subject
            subject = Subject(
                common_name=validated_data["common_name"],
                country_name=validated_data["country_name"],
                organization_name=validated_data["organization_name"],
            )

            common_name = subject["common_name"]
            # Ensure the directory exists
            output_dir = "client_certs"
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            # Load the root CA
            ca = CertificateAuthority(
                cert_path="root_cert/root_ca_cert.pem", key_path="root_cert/root_ca.key"
            )

            # Generate client certificate signed by the root CA
            client_cert_gen = ClientCertificateGenerator(output_dir=output_dir)
            client_cert = client_cert_gen.generate_signed_certificate(
                subject, ca, common_name, f"{common_name}_cert"
            )

            # Read the generated certificate and key
            cert_path = os.path.join(output_dir, f"{common_name}_cert.pem")
            key_path = os.path.join(output_dir, f"{common_name}.key")

            with open(cert_path, "r") as cert_file:
                cert_data = cert_file.read()
            with open(key_path, "r") as key_file:
                key_data = key_file.read()

            # Save to database
            ClientCertificate.objects.create(
                user=user,
                common_name=common_name,
                certificate=cert_data,
                private_key=key_data,
            )

            return Response({"certificate": cert_data}, status=status.HTTP_200_OK)
        else:
            return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class RetrieveUserCertificatesView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Retireve a client certificate",
        operation_description="This endpoint returns a signed certificate for the logged in user.",
        tags=["Certificates"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        responses={
            201: openapi.Response(
                description=" Successful",
                schema=ClientCertificateDetailSerializer,
            ),
            404: openapi.Response(description="Certificate not found"),
        },
    )
    def get(self, request):
        user = request.user
        certificates = ClientCertificate.objects.filter(user=user)
        serializer = ClientCertificateDetailSerializer(certificates, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
