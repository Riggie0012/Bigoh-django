from django.http import JsonResponse
from django.shortcuts import render
from django.db import connection


def home(request):
    return render(request, 'store/home.html')


def db_health(request):
    try:
        with connection.cursor() as cur:
            cur.execute("SELECT 1")
            row = cur.fetchone()
        ok = bool(row and row[0] == 1)
    except Exception as exc:
        return JsonResponse({"ok": False, "error": str(exc)}, status=500)
    return JsonResponse({"ok": ok})
