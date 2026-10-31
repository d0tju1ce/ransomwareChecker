# Generates app.ico: dark rounded tile (terminal look of the app) with a small green shield.
# Every size is drawn separately so even 16x16 stays sharp. Run once; build.cmd only embeds the .ico file.
# With -Preview <png> it only renders a preview in several sizes.
param([string]$Preview)
Add-Type -AssemblyName System.Drawing
$ErrorActionPreference = 'Stop'

function New-RoundedRect([single]$x, [single]$y, [single]$w, [single]$h, [single]$r) {
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = $r * 2
    $p.AddArc($x, $y, $d, $d, 180, 90)
    $p.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $p.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $p.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $p.CloseFigure()
    $p
}

# Shield outline as a closed path, coordinates relative to the icon size
function New-Shield([single]$s) {
    $f = { param($v) [single]($v * $s) }
    $p = New-Object System.Drawing.Drawing2D.GraphicsPath
    $p.AddLine((& $f 0.50), (& $f 0.16), (& $f 0.77), (& $f 0.26))
    $p.AddBezier((& $f 0.77), (& $f 0.26), (& $f 0.78), (& $f 0.56), (& $f 0.68), (& $f 0.73), (& $f 0.50), (& $f 0.85))
    $p.AddBezier((& $f 0.50), (& $f 0.85), (& $f 0.32), (& $f 0.73), (& $f 0.22), (& $f 0.56), (& $f 0.23), (& $f 0.26))
    $p.CloseFigure()
    $p
}

function New-IconBitmap([int]$size, [System.Drawing.Color]$c1, [System.Drawing.Color]$c2) {
    $bmp = New-Object System.Drawing.Bitmap $size, $size, ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'
    $g.PixelOffsetMode = 'HighQuality'
    $g.Clear([System.Drawing.Color]::Transparent)
    $s = [single]$size
    $tile = New-RoundedRect 0 0 ($s - 0.5) ($s - 0.5) ([single]($s * 0.22))
    $grad = New-Object System.Drawing.Drawing2D.LinearGradientBrush ((New-Object System.Drawing.PointF 0, 0)), ((New-Object System.Drawing.PointF $s, $s)), $c1, $c2
    $g.FillPath($grad, $tile)

    # Thin white frame keeps the dark tile visible on a dark taskbar
    if ($size -ge 32) {
        $frame = New-Object System.Drawing.Pen ([System.Drawing.Color]::FromArgb(110, 210, 210, 210)), ([single][Math]::Max(1, $s * 0.025))
        $g.DrawPath($frame, (New-RoundedRect ($s * 0.02) ($s * 0.02) ($s * 0.955) ($s * 0.955) ([single]($s * 0.2))))
    }
    $green = [System.Drawing.Color]::FromArgb(210, 210, 210)   # retro: off-white
    $shield = New-Shield $s
    # Smaller shield: scaled to 72 % around the center of the tile
    $m = New-Object System.Drawing.Drawing2D.Matrix
    $m.Translate([single]($s / 2), [single]($s / 2))
    $m.Scale(0.72, 0.72)
    $m.Translate([single](-$s / 2), [single](-$s / 2))
    $shield.Transform($m)
    if ($size -le 24) {
        $g.FillPath((New-Object System.Drawing.SolidBrush $green), $shield)
    } else {
        $pen = New-Object System.Drawing.Pen $green, ([single]($s * 0.07))
        $pen.LineJoin = 'Round'
        $g.DrawPath($pen, $shield)
    }
    $g.Dispose()
    $bmp
}

function Get-IconImageBytes([System.Drawing.Bitmap]$bmp) {
    $size = $bmp.Width
    $ms = New-Object System.IO.MemoryStream
    if ($size -ge 256) {
        $bmp.Save($ms, [System.Drawing.Imaging.ImageFormat]::Png)
    } else {
        # 32-bit DIB (BITMAPINFOHEADER + bottom-up BGRA pixels + empty AND mask) - most compatible
        $bw = New-Object System.IO.BinaryWriter $ms
        $maskStride = [int][Math]::Ceiling($size / 32) * 4
        $bw.Write([uint32]40); $bw.Write([int32]$size); $bw.Write([int32]($size * 2))
        $bw.Write([uint16]1); $bw.Write([uint16]32); $bw.Write([uint32]0)
        $bw.Write([uint32]($size * $size * 4 + $maskStride * $size))
        $bw.Write([int32]0); $bw.Write([int32]0); $bw.Write([uint32]0); $bw.Write([uint32]0)
        $data = $bmp.LockBits((New-Object System.Drawing.Rectangle 0, 0, $size, $size), 'ReadOnly', ([System.Drawing.Imaging.PixelFormat]::Format32bppArgb))
        $row = New-Object byte[] ($size * 4)
        for ($y = $size - 1; $y -ge 0; $y--) {
            [System.Runtime.InteropServices.Marshal]::Copy([IntPtr]($data.Scan0.ToInt64() + $y * $data.Stride), $row, 0, $row.Length)
            $bw.Write($row)
        }
        $bmp.UnlockBits($data)
        $bw.Write((New-Object byte[] ($maskStride * $size)))
        $bw.Flush()
    }
    , $ms.ToArray()
}

# Dark green-black gradient (background of the app)
$c1 = [System.Drawing.Color]::FromArgb(30, 30, 30)
$c2 = [System.Drawing.Color]::FromArgb(0, 0, 0)
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Preview) {
    $out = New-Object System.Drawing.Bitmap 520, 280
    $g = [System.Drawing.Graphics]::FromImage($out)
    $g.Clear([System.Drawing.Color]::FromArgb(243, 244, 246))
    $x = 10
    foreach ($sz in 16, 24, 32, 48, 64, 128, 256) {
        $b = New-IconBitmap $sz $c1 $c2
        $g.DrawImage($b, $x, 10, $sz, $sz)
        $x += $sz + 10
        $b.Dispose()
    }
    $g.Dispose()
    $out.Save($Preview)
    return
}

$sizes = 16, 20, 24, 32, 40, 48, 64, 128, 256
$images = foreach ($sz in $sizes) { $b = New-IconBitmap $sz $c1 $c2; , (Get-IconImageBytes $b); $b.Dispose() }
$fs = [System.IO.File]::Create((Join-Path $here 'app.ico'))
$bw = New-Object System.IO.BinaryWriter $fs
$bw.Write([uint16]0); $bw.Write([uint16]1); $bw.Write([uint16]$sizes.Count)
$offset = 6 + 16 * $sizes.Count
for ($i = 0; $i -lt $sizes.Count; $i++) {
    $dim = if ($sizes[$i] -ge 256) { 0 } else { $sizes[$i] }
    $bw.Write([byte]$dim); $bw.Write([byte]$dim); $bw.Write([byte]0); $bw.Write([byte]0)
    $bw.Write([uint16]1); $bw.Write([uint16]32)
    $bw.Write([uint32]$images[$i].Length); $bw.Write([uint32]$offset)
    $offset += $images[$i].Length
}
foreach ($img in $images) { $bw.Write($img) }
$bw.Close()
'app.ico written'
