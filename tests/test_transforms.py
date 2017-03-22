import logging
import unittest
from datetime import datetime, timedelta, timezone

from aw_core.models import Event
from aw_core.transforms import full_chunk, label_chunk, filter_period_intersect, include_labels, exclude_labels


class ChunkTest(unittest.TestCase):
    # Tests the chunk transform

    def test_chunk_full(self):
        eventcount = 8
        events = []
        for i in range(eventcount):
            events.append(Event(label="test",
                                keyvals={"key"+str(i%2): "val"+str(i%4)},
                                timestamp=datetime.now(timezone.utc) + timedelta(seconds=i),
                                duration=timedelta(seconds=1)))
        res = full_chunk(events)
        logging.debug(res)
        assert res['eventcount'] == eventcount
        assert res['duration'] == timedelta(seconds=eventcount)
        print(res)
        assert res['chunks']['test']['duration'] == timedelta(seconds=eventcount)
        assert res['chunks']['test']['keyvals']['key0']['duration'] == timedelta(seconds=eventcount/2)
        assert res['chunks']['test']['keyvals']['key0']['values']['val0']['duration'] == timedelta(seconds=eventcount/4)
        assert res['chunks']['test']['keyvals']['key0']['values']['val2']['duration'] == timedelta(seconds=eventcount/4)
        assert res['chunks']['test']['duration'] == timedelta(seconds=eventcount)
        assert res['chunks']['test']['keyvals']['key1']['duration'] == timedelta(seconds=eventcount/2)
        assert res['chunks']['test']['keyvals']['key1']['values']['val1']['duration'] == timedelta(seconds=eventcount/4)
        assert res['chunks']['test']['keyvals']['key1']['values']['val3']['duration'] == timedelta(seconds=eventcount/4)


    def test_chunk_label(self):
        eventcount = 8
        events = []
        for i in range(eventcount):
            events.append(Event(label="test",
                                timestamp=datetime.now(timezone.utc) + timedelta(seconds=i),
                                duration=timedelta(seconds=1)))
        res = label_chunk(events)
        logging.debug(res)
        assert res['eventcount'] == eventcount
        assert res['duration'] == timedelta(seconds=eventcount)
        print(res)
        assert res['chunks']['test']['duration'] == timedelta(seconds=eventcount)


class IncludeLabelsTest(unittest.TestCase):
    def test_include_labels(self):
        labels = ["a","c"]
        events = [
            Event(label="a"),
            Event(label="b"),
            Event(label="c"),
        ]
        included_labels = include_labels(events, labels)
        excluded_labels = exclude_labels(events, labels)
        assert len(included_labels) == 2
        assert len(excluded_labels) == 1


class FilterPeriodIntersectTest(unittest.TestCase):
    def test_filter_period_intersect(self):
        td1h = timedelta(hours=1)
        td30min = timedelta(minutes=30)
        now = datetime.now()

        # Filter 1h event with another 1h event at a 30min offset
        to_filter = [Event(label="lala", timestamp=now, duration=td1h)]
        filter_with = [Event(timestamp=now + timedelta(minutes=30), duration=td1h)]
        filtered_events = filter_period_intersect(to_filter, filter_with)
        assert filtered_events[0].duration == timedelta(minutes=30)

        # Filter 2x 30min events with a 15min gap with another 45min event in between intersecting both
        to_filter = [
            Event(label="lala", timestamp=now, duration=td30min),
            Event(label="lala", timestamp=now + timedelta(minutes=45), duration=td30min)
        ]
        filter_with = [Event(timestamp=now + timedelta(minutes=15), duration=timedelta(minutes=45))]
        filtered_events = filter_period_intersect(to_filter, filter_with)
        assert filtered_events[0].duration == timedelta(minutes=15)
        assert filtered_events[1].duration == timedelta(minutes=15)
