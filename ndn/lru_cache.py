from collections import deque


class LRUCache (object):
  """
  An LRU cache which is represented as a doubly linked list.
  The left end is the LRU side, and the right end is the MRU side.

  Time complexity of operations:
  insert: O(1)
  delete: O(N)
  update: O(N)
  """

  def __init__ (self, max_len):
    self.doubly_ll = deque()
    self.items = set()
    self.max_len = max_len

  def insert (self, to_insert):
    """Append `to_insert` to MRU side"""
    if to_insert in self.items:
      return
    if self.items and len(self.items) == self.max_len:
      lru_del_item = self.doubly_ll.popleft()
      self.items.remove(lru_del_item)
    self.doubly_ll.append(to_insert)
    self.items.add(to_insert)

  def delete (self, to_del):
    if not self.items or to_del not in self.items:
      return
    self.doubly_ll.remove(to_del)
    self.items.remove(to_del)

  def update (self, to_update):
    """Move `to_update` to MRU side"""
    if to_update not in self.items:
      return
    self.doubly_ll.remove(to_update)
    self.doubly_ll.append(to_update)

  def exists (self, to_search):
    return to_search in self.items


def test_LRUCache ():
  # test size 1 cache
  lru = LRUCache(1)
  assert lru.items == set()
  assert list(lru.doubly_ll) == []
  lru.insert(1)
  assert lru.items == {1}
  assert list(lru.doubly_ll) == [1]
  lru.delete(1)
  assert lru.items == set()
  assert list(lru.doubly_ll) == []
  lru.update(1)
  assert lru.items == set()
  assert list(lru.doubly_ll) == []
  lru.insert(1)
  lru.update(1)
  assert lru.items == {1}
  assert list(lru.doubly_ll) == [1]

  # test size 2 cache
  lru = LRUCache(2)
  lru.insert(1)
  lru.insert(2)
  lru.insert(3)
  assert lru.items == {2, 3}
  assert list(lru.doubly_ll) == [2, 3]
  lru.update(2)
  assert lru.items == {2, 3}
  assert list(lru.doubly_ll) == [3, 2]
  lru.update(1)
  assert lru.items == {2, 3}
  assert list(lru.doubly_ll) == [3, 2]
  lru.update(2)
  assert lru.items == {3, 2}
  assert list(lru.doubly_ll) == [3, 2]
  lru.delete(2)
  assert lru.items == {3}
  assert list(lru.doubly_ll) == [3]
  lru.delete(4)
  assert lru.items == {3}
  assert list(lru.doubly_ll) == [3]


if __name__ == "__main__":
  test_LRUCache()
