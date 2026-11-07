using TryZ.Data;

namespace TryZ.Views;

/// <summary>"What to fix first": findings ranked by exploitation risk, grouped into remediation actions.</summary>
internal sealed class RemediationView : ModuleView
{
    public RemediationView(IShell shell) : base(shell) { }

    public override string Title => "Remediation Plan";
    public override IconId IconKind => IconId.Remediation;

    public override void SyncData() { }
}
