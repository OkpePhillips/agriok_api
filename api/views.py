from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
import requests
from django.conf import settings
from rest_framework.permissions import IsAuthenticated, IsAdminUser
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
    Post,
    Payment,
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
)
from .permissions import IsOwnerOrAdmin
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import get_object_or_404
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.http import JsonResponse
from rave_python import Rave, RaveExceptions


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
        response = Response({"detail": "Logout successful"}, status=status.HTTP_200_OK)
        response.delete_cookie("access_token")
        return response


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

    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

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

    permission_classes = [IsAuthenticated]

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
        permission_classes = [IsAdminUser]
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

    permission_classes = [IsAuthenticated]

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
        permission_classes = [IsAdminUser]
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
        permission_classes = [IsAdminUser]
        insight = self.get_object(pk)
        if insight is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        insight.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ProductAPIView(APIView):
    """
    View to get and create products.
    """

    @swagger_auto_schema(
        operation_summary="Get products",
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
            )
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
        permission_classes = [IsAdminUser]
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductDetailAPIView(APIView):
    """
    View to retrieve, update and delete specific products.
    """

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
        operation_summary="Update specific product",
        operation_description="This endpoint allows an admin to update a specific product by its ID.",
        tags=["Products"],
        manual_parameters=[
            openapi.Parameter(
                "Authorization",
                openapi.IN_HEADER,
                description="Access Token",
                type=openapi.TYPE_STRING,
                required=True,
            )
        ],
        request_body=ProductSerializer,
        responses={
            200: openapi.Response(
                description="Product updated successfully", schema=ProductSerializer
            ),
            404: openapi.Response(description="Product not found"),
            400: openapi.Response(description="Bad Request - validation errors"),
        },
    )
    def put(self, request, pk):
        permission_classes = [IsAdminUser]
        product = self.get_object(pk)
        if product is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = ProductSerializer(product, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Delete specific product",
        operation_description="This endpoint allows an admin to delete a specific product by its ID.",
        tags=["Products"],
        responses={
            204: openapi.Response(description="Product deleted successfully"),
            404: openapi.Response(description="Product not found"),
        },
    )
    def delete(self, request, pk):
        permission_classes = [IsAdminUser]
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
    View to retrieve, update and delete specific cart items.
    """

    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Get specific cart item",
        operation_description="This endpoint allows users to retrieve a specific cart item by its ID.",
        tags=["Cart"],
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
        serializer = CartSerializer(cart_item)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Update specific cart item",
        operation_description="This endpoint allows users to update a specific cart item by its ID.",
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
        request_body=CartSerializer,
        responses={
            200: openapi.Response(
                description="Cart item updated successfully", schema=CartSerializer
            ),
            404: openapi.Response(description="Cart item not found"),
            400: openapi.Response(description="Bad Request - validation errors"),
        },
    )
    def put(self, request, pk):
        cart_item = self.get_object(pk)
        if cart_item is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = CartSerializer(cart_item, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Delete specific cart item",
        operation_description="This endpoint allows users to delete a specific cart item by its ID.",
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


class PlaceOrderView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Place an order",
        operation_description="This endpoint allows a user to place an order based on the items in their cart.",
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
            {"detail": "Order placed successfully"}, status=status.HTTP_201_CREATED
        )


class OrderHistoryView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="Retrieve order history",
        operation_description="This endpoint allows a user to retrieve their order history.",
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
        print(user)
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
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_summary="List all posts",
        operation_description="This endpoint allows users to retrieve all posts.",
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
        """List all posts"""
        posts = Post.objects.all()
        serializer = PostSerializer(posts, many=True)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Create a new post",
        operation_description="This endpoint allows users to create a new post.",
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
        serializer = PostSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save(user=request.user)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class PostDetailView(APIView):
    permission_classes = [IsAuthenticated]

    def get_object(self, pk, user):
        return get_object_or_404(Post, pk=pk, user=user)

    @swagger_auto_schema(
        operation_summary="Retrieve a specific post",
        operation_description="This endpoint allows users to retrieve a specific post by its ID.",
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
            200: openapi.Response(description="Post details", schema=PostSerializer),
            404: openapi.Response(description="Post not found"),
            401: "Unauthorized",
        },
    )
    def get(self, request, pk):
        """Retrieve a specific post"""
        post = get_object_or_404(Post, pk=pk)
        serializer = PostSerializer(post)
        return Response(serializer.data)

    @swagger_auto_schema(
        operation_summary="Update an existing post",
        operation_description="This endpoint allows users to update a specific post by its ID.",
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
        post = self.get_object(pk, request.user)
        serializer = PostSerializer(post, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_summary="Delete a post",
        operation_description="This endpoint allows users to delete a specific post by its ID.",
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
        post = self.get_object(pk, request.user)
        post.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class MTNMomoPaymentView(APIView):
    """
    View to handle payments via MTN MoMo.
    """

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
