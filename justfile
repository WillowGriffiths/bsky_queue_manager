[parallel]
dev: tailwind django

tailwind:
    pnpm exec tailwindcss --watch \
        -i ./bsky_queue_manager/style.css \
        -o generated/bsky_queue_manager/style.css

django:
    DJANGO_DEBUG=y poetry run python manage.py runserver
