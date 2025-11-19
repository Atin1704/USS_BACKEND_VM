import json
from typing import Iterable, List

from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt

from core.services.model_inference import predict_urls


def ping(request):
    return JsonResponse({'status': 'ok'})


def _validate_features(candidates: Iterable[str]) -> List[str]:
    items: List[str] = []
    for candidate in candidates:
        if candidate is None:
            continue
        if not isinstance(candidate, str):
            raise ValueError('Each URL must be provided as a string.')
        value = candidate.strip()
        if value:
            items.append(value)
    if not items:
        raise ValueError('At least one non-empty URL must be provided.')
    return items


@csrf_exempt
def model_get_score(request, url_value=None):
    if request.method == 'POST':
        try:
            payload = json.loads(request.body or '{}')
        except json.JSONDecodeError:
            return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

        features = payload.get('features')
        if not isinstance(features, list):
            return JsonResponse({'error': '"features" must be a list of URL strings.'}, status=400)
        feature_list = features
    elif request.method == 'GET':
        query_urls = request.GET.getlist('url') or request.GET.getlist('features')
        if url_value and url_value not in query_urls:
            query_urls = [url_value] + query_urls
        feature_list = query_urls if query_urls else ([url_value] if url_value else [])
    else:
        return JsonResponse({'error': f'Method {request.method} not allowed.'}, status=405)

    try:
        features_clean = _validate_features(feature_list)
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)

    try:
        predictions = predict_urls(features_clean)
    except FileNotFoundError as exc:
        return JsonResponse({'error': str(exc)}, status=500)
    except Exception as exc:  # defensive: surfaces unexpected inference issues
        return JsonResponse({'error': str(exc)}, status=500)

    return JsonResponse({'prediction': predictions})
