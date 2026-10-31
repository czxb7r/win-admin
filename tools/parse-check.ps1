# Parse each file with the PowerShell parser and report syntax errors.
# pwsh 7 accepts some syntax Windows PowerShell 5.1 rejects (?:, ??, &&); avoid those by convention.
$bad = 0
foreach ($f in $args) {
    $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile((Resolve-Path $f).Path, [ref]$null, [ref]$errs)
    foreach ($e in $errs) {
        "{0}:{1}: {2}" -f $f, $e.Extent.StartLineNumber, $e.Message
        $bad = 1
    }
}
exit $bad
