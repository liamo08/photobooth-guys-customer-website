#!/bin/bash
cd "/opt/photobooth guys website/admin"
exec "/opt/photobooth guys website/admin/venv/bin/gunicorn" \
    --bind 127.0.0.1:5050 \
    --workers 2 \
    --timeout 120 \
    app:app
