using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class UploadController : ControllerBase
{
    // Config
    private static readonly HashSet<string> AllowedExtensions = new(StringComparer.OrdinalIgnoreCase)
    { ".png", ".jpg", ".jpeg", ".gif"};

    private static readonly HashSet<string> AllowedMimeTypes = new(StringComparer.OrdinalIgnoreCase)
    { "image/png", "image/jpeg", "image/gif"};

    private const long MaxFileBytes = 5 * 1024 * 1024; // 5 MB (must match/fit under Kestrel limit)

    [HttpPost]
    [RequestSizeLimit(MaxFileBytes)] // Controller-level size guard (works with Kestrel limit)
    public async Task<IActionResult> Upload([FromForm] IFormFile file)
    {
        Console.WriteLine("Started Upload");
        if (file is null || file.Length == 0)
            return BadRequest(new { error = "No file uploaded." });
        
        Console.WriteLine("file.length "+file.Length);
        //check 1 - file name check 
        if (file.Length > MaxFileBytes)
            return BadRequest(new { error = $"File exceeds {MaxFileBytes} bytes." });

        //check 2 - extension check 
        var ext = Path.GetExtension(file.FileName);
        Console.WriteLine("file.ext "+ext);
        if (string.IsNullOrWhiteSpace(ext) || !AllowedExtensions.Contains(ext))
            return BadRequest(new { error = "File type/extension not allowed." });

        Console.WriteLine("file.ContentType "+file.ContentType);
        //check 3 - allowed mime type check 
        if (!AllowedMimeTypes.Contains(file.ContentType))
            return BadRequest(new { error = "MIME type not allowed." });

        // check 4 - safe base directory check 
        var uploadsRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "wwwroot", "uploads"));
        Console.WriteLine("uploadsRoot "+uploadsRoot);
        Directory.CreateDirectory(uploadsRoot);

        //check 5 - random uploaded file name used instead of user provided 
        var safeName = $"{Guid.NewGuid():N}{ext}";
        var combined = Path.Combine(uploadsRoot, safeName);
        Console.WriteLine("combined safe name  "+combined);

        // check 6 - Path traversal defense: ensure final target stays inside uploadsRoot
        var fullPath = Path.GetFullPath(combined);
        Console.WriteLine("fullPath  "+fullPath);
        if (!fullPath.StartsWith(uploadsRoot, StringComparison.Ordinal))
            return BadRequest(new { error = "Invalid path." });

        // check 7 - Save securely (CreateNew avoids overwriting existing file by accident)
        await using (var fs = new FileStream(fullPath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 64 * 1024, FileOptions.WriteThrough))
        {
            Console.WriteLine("uploading the file ...");
            // Basic "magic number" (16 bytes are checked) sniffing to catch content-type spoofing
            // Read a small head buffer first
            using var headStream = file.OpenReadStream();
            var head = new byte[Math.Min(16, headStream.Length)];
            _ = await headStream.ReadAsync(head);

            if (!SniffAllowed(head, ext))
                return BadRequest(new { error = "File content does not match declared type." });

            // Reset and copy full stream
            headStream.Position = 0;
            await headStream.CopyToAsync(fs);
        }

        var publicUrl = $"/uploads/{safeName}";
        Console.WriteLine("publicUrl ..."+publicUrl);
        return Ok(new
        {
            success = true,
            file = new
            {
                id = Path.GetFileNameWithoutExtension(safeName), // or DB id
                originalName = Path.GetFileName(file.FileName),
                storedName = safeName,
                size = file.Length,
                contentType = file.ContentType,
                url = publicUrl
            }
        });
    }

    // Minimal signature checks (extend as needed)
    private static bool SniffAllowed(ReadOnlySpan<byte> head, string ext)
    {
        // JPEG: FF D8 FF
        static bool IsJpeg(ReadOnlySpan<byte> h) =>
            h.Length >= 3 && h[0] == 0xFF && h[1] == 0xD8 && h[2] == 0xFF;

        // PNG: 89 50 4E 47 0D 0A 1A 0A
        static bool IsPng(ReadOnlySpan<byte> h) =>
            h.Length >= 8 && h[0] == 0x89 && h[1] == 0x50 && h[2] == 0x4E && h[3] == 0x47 &&
            h[4] == 0x0D && h[5] == 0x0A && h[6] == 0x1A && h[7] == 0x0A;

        // GIF: "GIF87a" or "GIF89a"
        static bool IsGif(ReadOnlySpan<byte> h) =>
            h.Length >= 6 && h[0] == (byte)'G' && h[1] == (byte)'I' && h[2] == (byte)'F' &&
            h[3] == (byte)'8' && (h[4] == (byte)'7' || h[4] == (byte)'9') && h[5] == (byte)'a';

        return ext.ToLowerInvariant() switch
        {
            ".jpg" or ".jpeg" => IsJpeg(head),
            ".png"            => IsPng(head),
            ".gif"            => IsGif(head),
            _                 => false
        };
    }
}