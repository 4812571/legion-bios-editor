# Release build with local paths remapped, so the .efi doesn't embed the
# builder's home directory (dependency panic locations otherwise do).
$cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
$sep = [char]0x1f
$env:CARGO_ENCODED_RUSTFLAGS = @(
    "--remap-path-prefix=$cargoHome=cargo"
    "--remap-path-prefix=$PSScriptRoot=routecfg"
) -join $sep
Push-Location $PSScriptRoot
try {
    cargo build --release --target x86_64-unknown-uefi
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed ($LASTEXITCODE)" }
    $out = Join-Path $PSScriptRoot 'target\x86_64-unknown-uefi\release\routecfg.efi'
    "{0}  {1}" -f (Get-FileHash $out).Hash, $out
} finally {
    Remove-Item Env:\CARGO_ENCODED_RUSTFLAGS
    Pop-Location
}
