import jwt, json
import datetime
from django.contrib.auth.models import User
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.hashers import make_password
from django.conf import settings

SECRET_KEY = settings.SECRET_KEY  # Use Django's SECRET_KEY

def generate_jwt_token(user):
    """Generate JWT token for the user."""
    payload = {
        "user_id": user.id,
        "username": user.username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(days=1),
        "iat": datetime.datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

@csrf_exempt
def signup(request):
    """Handles user signup and returns JWT"""
    if request.method == "POST":
        try:
            data = json.loads(request.body)
            username = data.get("username")
            password = data.get("pwd")

            # Check if user already exists
            if User.objects.filter(username=username).exists():
                return JsonResponse({"error": "Username already taken"}, status=400)

            # Create new user
            user = User.objects.create(username=username, password=make_password(password))

            # Generate JWT token
            token = generate_jwt_token(user)

            response = JsonResponse({"message": "Signup successful", "token": token})
            response.set_cookie("jwt_token", token, httponly=True, samesite="Strict")
            return response

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request123"}, status=400)

