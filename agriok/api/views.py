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
)
from .permissions import IsOwnerOrAdmin
from django.contrib.auth import update_session_auth_hash
from django.shortcuts import get_object_or_404


class RegisterView(APIView):
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
    def post(self, request):
        serializer = EmailLoginSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.validated_data["user"]
            refresh = RefreshToken.for_user(user)
            response = Response({"user_id": user.id}, status=status.HTTP_201_CREATED)

            # Set the access token in the cookie
            response.set_cookie(
                key="access_token",
                value=str(refresh.access_token),
                httponly=True,
                secure=True,
            )
            return response
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class UpdateProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)

    def put(self, request):
        user = request.user
        serializer = UserUpdateSerializer(user, data=request.data, partial=True)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_200_OK)

        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    permission_classes = [IsAuthenticated]

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
    def get(self, request):
        insights = Insight.objects.filter(user=request.user)
        serializer = FarmInsightSerializer(insights, many=True)
        return Response(serializer.data)

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

    def delete(self, request, pk):
        permission_classes = [IsAdminUser]
        insight = self.get_object(pk)
        if insight is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        insight.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ProductAPIView(APIView):
    def get(self, request):
        products = Product.objects.all()
        serializer = ProductSerializer(products, many=True)
        return Response(serializer.data)

    def post(self, request):
        permission_classes = [IsAdminUser]
        serializer = ProductSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProductDetailAPIView(APIView):
    def get_object(self, pk):
        try:
            return Product.objects.get(pk=pk)
        except Product.DoesNotExist:
            return None

    def get(self, request, pk):
        product = self.get_object(pk)
        if product is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = ProductSerializer(product)
        return Response(serializer.data)

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

    def delete(self, request, pk):
        permission_classes = [IsAdminUser]
        product = self.get_object(pk)
        if product is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        product.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class AddToCartView(APIView):
    permission_classes = [IsAuthenticated]

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


class CartView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        cart = get_object_or_404(Cart, user=request.user)
        serializer = CartSerializer(cart)
        return Response(serializer.data)


class PlaceOrderView(APIView):
    permission_classes = [IsAuthenticated]

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

    def get(self, request):
        orders = Order.objects.filter(user=request.user)
        serializer = OrderSerializer(orders, many=True)
        return Response(serializer.data)


class UserAPIView(APIView):

    permission_classes = [IsAdminUser]

    def get(self, request, pk=None):
        """Admin Processes to retrieve all users"""
        if pk:
            user = get_object_or_404(CustomUser, pk=pk)
            serializer = UserProfileSerializer(user)
        else:
            users = CustomUser.objects.all()
            serializer = UserProfileSerializer(users, many=True)
        return Response(serializer.data)

    def delete(self, request, pk):
        """Admin Process to delete a specific user"""
        user = get_object_or_404(CustomUser, pk=pk)
        user.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)


class FarmlandAPIView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        farmlands = Farmland.objects.filter(user=request.user)
        serializer = FarmlandSerializer(farmlands, many=True)
        return Response(serializer.data)

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

    def get(self, request, pk):
        farmland = self.get_object(pk)
        if farmland is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        serializer = FarmlandSerializer(farmland)
        return Response(serializer.data)

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

    def delete(self, request, pk):
        farmland = self.get_object(pk)
        if farmland is None:
            return Response(status=status.HTTP_404_NOT_FOUND)
        self.check_object_permissions(request, farmland)
        farmland.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
