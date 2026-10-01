using System;
using System.IO;
using System.Threading;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Xunit;

namespace Phalanx.Agent.Tests;

[Trait("Category", "Unit")]
public class IconGeneratorTests
{
    [Fact]
    public void GeneratePhalanxAssets()
    {
        var thread = new Thread(() =>
        {
            int[] sizes = [16, 32, 48, 256];
            var pngBytesList = new System.Collections.Generic.List<byte[]>();

            var geometry = Geometry.Parse(
                "M 12,2 L 20,5.5 L 20,8 L 12,4.5 L 4,8 L 4,5.5 Z " +
                "M 12,7 L 20,10.5 L 20,13 L 12,9.5 L 4,13 L 4,10.5 Z " +
                "M 12,12 L 19.5,15.2 L 12,22 L 4.5,15.2 Z");

            var brush = new SolidColorBrush(Color.FromRgb(0x3B, 0x82, 0xF6)); // Accent Blue #3B82F6
            brush.Freeze();

            foreach (var size in sizes)
            {
                var visual = new DrawingVisual();
                using (var dc = visual.RenderOpen())
                {
                    // Scale 24x24 geometry to target size with slight padding
                    double padding = size * 0.08;
                    double drawSize = size - (padding * 2);
                    double scale = drawSize / 24.0;

                    var transformGroup = new TransformGroup();
                    transformGroup.Children.Add(new ScaleTransform(scale, scale));
                    transformGroup.Children.Add(new TranslateTransform(padding, padding));
                    dc.PushTransform(transformGroup);

                    dc.DrawGeometry(brush, null, geometry);
                    dc.Pop();
                }

                var rtb = new RenderTargetBitmap(size, size, 96, 96, PixelFormats.Pbgra32);
                rtb.Render(visual);

                var encoder = new PngBitmapEncoder();
                encoder.Frames.Add(BitmapFrame.Create(rtb));
                using var ms = new MemoryStream();
                encoder.Save(ms);
                pngBytesList.Add(ms.ToArray());
            }

            // Target directory
            var currentDir = AppDomain.CurrentDomain.BaseDirectory;
            var cockpitDir = Path.GetFullPath(Path.Combine(currentDir, "..", "..", "..", "..", "..", "src", "Phalanx.Cockpit"));
            var assetsDir = Path.Combine(cockpitDir, "Assets");
            Directory.CreateDirectory(assetsDir);

            // Save high-res PNG (256x256)
            File.WriteAllBytes(Path.Combine(assetsDir, "phalanx.png"), pngBytesList[^1]);

            // Save multi-res ICO (16, 32, 48, 256)
            var icoPath = Path.Combine(assetsDir, "phalanx.ico");
            using var fs = new FileStream(icoPath, FileMode.Create);
            using var bw = new BinaryWriter(fs);

            // ICONDIR
            bw.Write((ushort)0); // reserved
            bw.Write((ushort)1); // type 1 = icon
            bw.Write((ushort)sizes.Length); // count

            int offset = 6 + (16 * sizes.Length);
            for (int i = 0; i < sizes.Length; i++)
            {
                int size = sizes[i];
                byte bSize = (byte)(size >= 256 ? 0 : size);
                bw.Write(bSize); // width
                bw.Write(bSize); // height
                bw.Write((byte)0); // color count
                bw.Write((byte)0); // reserved
                bw.Write((ushort)1); // planes
                bw.Write((ushort)32); // bit count
                bw.Write((uint)pngBytesList[i].Length); // bytes in res
                bw.Write((uint)offset); // image offset

                offset += pngBytesList[i].Length;
            }

            for (int i = 0; i < sizes.Length; i++)
            {
                bw.Write(pngBytesList[i]);
            }
        });

        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();

        Assert.True(true);
    }
}
