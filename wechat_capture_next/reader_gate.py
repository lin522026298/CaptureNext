"""Concurrent read admission with a writer-preferred maintenance drain."""
import threading


class ReaderGate:
    def __init__(self):
        self.condition=threading.Condition()
        self.readers=0
        self.writer=False
        self.waiting_writers=0

    def acquire(self,blocking=True):
        with self.condition:
            if not blocking and (self.writer or self.waiting_writers):
                return False
            while self.writer or self.waiting_writers:
                self.condition.wait()
            self.readers+=1
            return True

    def release(self):
        with self.condition:
            if self.readers<=0:
                raise RuntimeError('no admitted reader')
            self.readers-=1
            self.condition.notify_all()

    def __enter__(self):
        with self.condition:
            self.waiting_writers+=1
            try:
                while self.writer or self.readers:
                    self.condition.wait()
                self.writer=True
            finally:
                self.waiting_writers-=1
        return self

    def __exit__(self,*_):
        with self.condition:
            self.writer=False
            self.condition.notify_all()
