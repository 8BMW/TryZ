param([string]$Out = (Join-Path $PSScriptRoot '..\assets\tryz.ico'))
Add-Type -AssemblyName System.Drawing

function Color($hex) { [System.Drawing.ColorTranslator]::FromHtml($hex) }

function Render([int]$size) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'Half'
    $g.ScaleTransform($size / 32.0, $size / 32.0)

    $rect = New-Object System.Drawing.RectangleF 0.5, 0.5, 31, 31
    $bg = New-Object System.Drawing.Drawing2D.LinearGradientBrush $rect, (Color '#3A3F45'), (Color '#141518'), 90.0
    $g.FillRectangle($bg, 0.5, 0.5, 31, 31)
    $pen = New-Object System.Drawing.Pen (Color '#08090A'), 1
    $g.DrawRectangle($pen, 0.5, 0.5, 31, 31)
    $hi = New-Object System.Drawing.Pen (Color '#5A6068'), 1
    $g.DrawLine($hi, 1.5, 1.5, 30.5, 1.5)
    $g.DrawLine($hi, 1.5, 1.5, 1.5, 30.5)

    $z = New-Object System.Drawing.Drawing2D.GraphicsPath
    $pts = @(
        (New-Object System.Drawing.PointF 5, 6), (New-Object System.Drawing.PointF 27, 6),
        (New-Object System.Drawing.PointF 27, 10), (New-Object System.Drawing.PointF 12, 22),
        (New-Object System.Drawing.PointF 27, 22), (New-Object System.Drawing.PointF 27, 26),
        (New-Object System.Drawing.PointF 5, 26), (New-Object System.Drawing.PointF 5, 22),
        (New-Object System.Drawing.PointF 20, 10), (New-Object System.Drawing.PointF 5, 10))
    $z.AddPolygon([System.Drawing.PointF[]]$pts)
    $zr = New-Object System.Drawing.RectangleF 5, 6, 22, 20
    $zb = New-Object System.Drawing.Drawing2D.LinearGradientBrush $zr, (Color '#D0362C'), (Color '#6D1717'), 90.0
    $g.FillPath($zb, $z)
    $g.DrawPath((New-Object System.Drawing.Pen (Color '#2A0808'), 0.8), $z)

    $blade = New-Object System.Drawing.Drawing2D.GraphicsPath
    $bp = @(
        (New-Object System.Drawing.PointF 24.5, 2.5), (New-Object System.Drawing.PointF 26.5, 4.5),
        (New-Object System.Drawing.PointF 12, 20), (New-Object System.Drawing.PointF 9.8, 17.8))
    $blade.AddPolygon([System.Drawing.PointF[]]$bp)
    $br = New-Object System.Drawing.RectangleF 9, 2, 18, 18
    $bb = New-Object System.Drawing.Drawing2D.LinearGradientBrush $br, (Color '#EEF1F5'), (Color '#8D96A3'), 45.0
    $g.FillPath($bb, $blade)
    $g.DrawPath((New-Object System.Drawing.Pen (Color '#14161A'), 0.7), $blade)

    $guard = New-Object System.Drawing.Pen (Color '#C8A45C'), 2.6
    $g.DrawLine($guard, 7.2, 15.2, 14.6, 22.6)
    $grip = New-Object System.Drawing.Pen (Color '#7A6434'), 2.4
    $g.DrawLine($grip, 10.4, 20.6, 6.6, 24.4)
    $pom = New-Object System.Drawing.SolidBrush (Color '#C8A45C')
    $g.FillEllipse($pom, 4.2, 23.6, 3.6, 3.6)
    $g.Dispose()
    return $bmp
}

function DibBytes($bmp) {
    $s = $bmp.Width
    $ms = New-Object System.IO.MemoryStream
    $w = New-Object System.IO.BinaryWriter $ms
    $w.Write([int]40); $w.Write([int]$s); $w.Write([int]($s * 2)); $w.Write([int16]1); $w.Write([int16]32)
    $w.Write([int]0); $w.Write([int]($s * $s * 4)); $w.Write([int]0); $w.Write([int]0); $w.Write([int]0); $w.Write([int]0)
    for ($y = $s - 1; $y -ge 0; $y--) {
        for ($x = 0; $x -lt $s; $x++) {
            $c = $bmp.GetPixel($x, $y)
            $w.Write([byte]$c.B); $w.Write([byte]$c.G); $w.Write([byte]$c.R); $w.Write([byte]$c.A)
        }
    }
    $maskStride = [int]([math]::Ceiling($s / 32.0) * 4)
    $w.Write((New-Object byte[] ($maskStride * $s)))
    $w.Flush()
    return ,$ms.ToArray()
}

$sizes = 16, 24, 32, 48, 64, 256
$frames = foreach ($s in $sizes) {
    $bmp = Render $s
    if ($s -ge 256) {
        $ms = New-Object System.IO.MemoryStream
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
        ,@($s, $ms.ToArray())
    } else {
        ,@($s, (DibBytes $bmp))
    }
    $bmp.Dispose()
}

$fs = [System.IO.File]::Create($Out)
$w = New-Object System.IO.BinaryWriter $fs
$w.Write([int16]0); $w.Write([int16]1); $w.Write([int16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
foreach ($f in $frames) {
    $s = $f[0]; $data = [byte[]]$f[1]
    $dim = if ($s -ge 256) { 0 } else { $s }
    $w.Write([byte]$dim); $w.Write([byte]$dim); $w.Write([byte]0); $w.Write([byte]0)
    $w.Write([int16]1); $w.Write([int16]32); $w.Write([int]$data.Length); $w.Write([int]$offset)
    $offset += $data.Length
}
foreach ($f in $frames) { $w.Write([byte[]]$f[1]) }
$w.Flush(); $fs.Close()
