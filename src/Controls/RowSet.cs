using TryZ.Data;

namespace TryZ.Controls;

internal sealed class Col<T> : GridColumn where T : class
{
    public Col(string title, int width, Func<T, string> text, CellKind kind = CellKind.Text) : base(title, width, kind)
    {
        Text = text;
    }

    public Func<T, string> Text { get; }
    public Comparison<T>? Compare { get; init; }
    public Func<T, Color?>? Color { get; init; }
    public Func<T, int>? Bar { get; init; }
}

internal sealed class RowSet<T> : IGridSource where T : class
{
    private readonly RowStore<T> _store;
    private readonly Col<T>[] _columns;
    private readonly List<T> _view = new();
    private readonly List<T> _pending = new();
    private int _consumed;
    private int _storeGeneration = -1;
    private int _mutation;
    private string _filter = string.Empty;
    private Func<T, bool>? _scope;
    private int _sortColumn = -1;
    private bool _descending;
    private int _orderVersion;

    public RowSet(RowStore<T> store, params Col<T>[] columns)
    {
        _store = store;
        _columns = columns;
    }

    public IReadOnlyList<GridColumn> Columns => _columns;
    public int Count => _view.Count;
    public int OrderVersion => _orderVersion;
    public int SortColumn => _sortColumn;
    public bool SortDescending => _descending;
    public IReadOnlyList<T> Rows => _view;

    public string GetText(int row, int col) => _columns[col].Text(_view[row]);
    public Color? GetColor(int row, int col) => _columns[col].Color?.Invoke(_view[row]);
    public int GetBar(int row, int col) => _columns[col].Bar?.Invoke(_view[row]) ?? 0;
    public object ItemAt(int row) => _view[row];
    public int IndexOf(object item) => item is T t ? _view.IndexOf(t) : -1;

    public void SetSort(int col, bool descending)
    {
        _sortColumn = col;
        _descending = descending;
        SortView();
        _orderVersion++;
    }

    public void ToggleSort(int col)
    {
        if (_sortColumn == col) _descending = !_descending;
        else { _sortColumn = col; _descending = false; }
        SortView();
        _orderVersion++;
    }

    public void SetScope(Func<T, bool>? scope)
    {
        _scope = scope;
        Rebuild();
    }

    public bool Sync(string filter)
    {
        if (_storeGeneration != _store.Generation || !string.Equals(filter, _filter, StringComparison.Ordinal))
        {
            _filter = filter;
            Rebuild();
            return true;
        }

        var items = _store.Items;
        bool changed = false;
        for (; _consumed < items.Count; _consumed++)
        {
            var item = items[_consumed];
            if (!Matches(item)) continue;
            changed = true;
            if (_sortColumn >= 0) _pending.Add(item);
            else _view.Add(item);
        }
        if (_pending.Count > 0)
        {
            MergePending();
            _orderVersion++;
        }
        if (_mutation != _store.MutationVersion)
        {
            _mutation = _store.MutationVersion;
            changed = true;
            if (_sortColumn >= 0)
            {
                SortView();
                _orderVersion++;
            }
        }
        return changed;
    }

    private void Rebuild()
    {
        _storeGeneration = _store.Generation;
        _mutation = _store.MutationVersion;
        var items = _store.Items;
        _view.Clear();
        _pending.Clear();
        for (int i = 0; i < items.Count; i++)
            if (Matches(items[i])) _view.Add(items[i]);
        _consumed = items.Count;
        SortView();
        _orderVersion++;
    }

    private bool Matches(T item)
    {
        if (_scope != null && !_scope(item)) return false;
        if (_filter.Length == 0) return true;
        foreach (var c in _columns)
            if (c.Kind != CellKind.Bar && c.Text(item).Contains(_filter, StringComparison.OrdinalIgnoreCase))
                return true;
        return false;
    }

    private Comparison<T>? ActiveComparison()
    {
        if (_sortColumn < 0) return null;
        var col = _columns[_sortColumn];
        Comparison<T> cmp = col.Compare ?? ((a, b) => string.CompareOrdinal(col.Text(a), col.Text(b)));
        if (_descending)
        {
            var inner = cmp;
            cmp = (a, b) => inner(b, a);
        }
        return cmp;
    }

    private void SortView()
    {
        var cmp = ActiveComparison();
        if (cmp != null) _view.Sort(cmp);
    }

    private void MergePending()
    {
        var cmp = ActiveComparison()!;
        _pending.Sort(cmp);
        var merged = new List<T>(_view.Count + _pending.Count);
        int i = 0, j = 0;
        while (i < _view.Count && j < _pending.Count)
            merged.Add(cmp(_view[i], _pending[j]) <= 0 ? _view[i++] : _pending[j++]);
        while (i < _view.Count) merged.Add(_view[i++]);
        while (j < _pending.Count) merged.Add(_pending[j++]);
        _view.Clear();
        _view.AddRange(merged);
        _pending.Clear();
    }
}
