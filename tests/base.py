from timeit import timeit

from sp_api.api import FulfillmentInbound
from sp_api.base.helpers import rate_limiter


def test_api_response_next_token():
    res = FulfillmentInbound().get_shipments(QueryType='SHIPMENT')
    assert res.next_token is not None


def test_rate_limiter():
    """Asserts @rate_limiter decorator halts the decorated function for the appropriate amount of seconds."""

    rate_per_second = 0.5

    @rate_limiter(rate=rate_per_second)
    def example_function():
        return

    min_time_for_two_calls = (1 / rate_per_second) * 1.01  # margin of error
    time_taken = timeit(example_function, number=2)

    assert min_time_for_two_calls <= time_taken, f'{min_time_for_two_calls=}, {time_taken=}'
    print('ok')


if __name__ == '__main__':
    test_rate_limiter()