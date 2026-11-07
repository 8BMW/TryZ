using TryZ.Data;

namespace TryZ.Views;

/// <summary>Differences between the current session and a saved baseline session.</summary>
internal sealed class CompareView : ModuleView
{
    public CompareView(IShell shell) : base(shell) { }

    public override string Title => "Scan Compare";
    public override IconId IconKind => IconId.Compare;

    public override void SyncData() { }
}
