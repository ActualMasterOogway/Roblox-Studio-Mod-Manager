using RobloxStudioModManager;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Utility
{
    public static class RobloxInternal
    {
        /// <summary>
        /// Applies an internal patch to the Studio binary.
        /// This method extracts the patch data from GitHub, extracts the signature and patch byte arrays,
        /// finds the signature in the Studio binary, replaces it with the patch bytes, and writes the patched binary.
        /// </summary>
        /// <param name="bootstrapper">
        /// An instance of StudioBootstrapper (or any object that can provide logging and file paths).
        /// In this example we assume the bootstrapper exposes a GetLocalStudioPath() method and EchoFeed event.
        /// </param>
        public static async Task Patch(StudioBootstrapper bootstrapper)
        {
            string studioPath = bootstrapper.GetLocalStudioPath();

            bootstrapper.Echo("Applying internal patch...");

            // URL for the Rust source code containing our patch definitions.
            string url = "https://raw.githubusercontent.com/7ap/internal-studio-patcher/main/src/main.rs";
            byte[] signature, patch;

            try
            {
                // Download the source and extract the signature and patch arrays.
                signature = await GetByteArrayFromWebsiteAsync(url, "SIGNATURE").ConfigureAwait(false);
                patch = await GetByteArrayFromWebsiteAsync(url, "PATCH").ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                bootstrapper.Echo("Error downloading patch data: " + ex.Message);
                return;
            }

            byte[] binary;
            try
            {
                binary = await Task.Run(() => File.ReadAllBytes(studioPath)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                bootstrapper.Echo("Error reading studio binary: " + ex.Message);
                return;
            }

            int offset = FindSequence(binary, signature);
            if (offset < 0)
            {
                if (FindSequence(binary, patch) < 0) {
                    bootstrapper.Echo("Signature not found in binary.");
                } else {
                    bootstrapper.Echo("Binary is already patched.");
                }
                return;
            }

            // Apply the patch: copy the patch bytes into the binary at the located offset.
            Array.Copy(patch, 0, binary, offset, patch.Length);

            try
            {
                await Task.Run(() => File.WriteAllBytes(studioPath, binary)).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                bootstrapper.Echo("Error writing patched binary: " + ex.Message);
                return;
            }

            bootstrapper.Echo("Internal patch applied successfully.");
        }

        /// <summary>
        /// Downloads the given URL as a string, uses a regular expression to extract a Rust constant's byte array,
        /// and returns the corresponding byte array.
        /// </summary>
        /// <param name="url">URL to download (should point to raw text)</param>
        /// <param name="constantName">Name of the constant to find (e.g., "SIGNATURE" or "PATCH")</param>
        /// <returns>Byte array extracted from the constant definition</returns>
        private static async Task<byte[]> GetByteArrayFromWebsiteAsync(string url, string constantName)
        {
            using (var HttpClient = new WebClient())
            {
                string content = await HttpClient.DownloadStringTaskAsync(url);

                // Regex to match the constant definition in the Rust source.
                // Matches:
                //   const CONSTANT_NAME: &[u8] = &[ ... ];
                string pattern = $@"const\s+{constantName}:\s*&\[u8\]\s*=\s*&\[\s*(.*?)\s*\];";
                var regex = new Regex(pattern, RegexOptions.Singleline);
                var match = regex.Match(content);
                if (!match.Success)
                    throw new Exception($"Could not find constant {constantName} in the website content.");

                // Extract the array contents and parse hex values.
                string arrayContent = match.Groups[1].Value;
                var hexRegex = new Regex(@"0x[0-9A-Fa-f]+");
                var matches = hexRegex.Matches(arrayContent);
                var bytes = new List<byte>();
                foreach (Match m in matches)
                {
                    bytes.Add(Convert.ToByte(m.Value, 16));
                }
                return bytes.ToArray();
            }
        }

        /// <summary>
        /// Searches for the occurrence of the byte sequence (needle) inside a larger byte array (haystack).
        /// Returns the zero-based index if found, or -1 if not found.
        /// </summary>
        private static int FindSequence(byte[] haystack, byte[] needle)
        {
            for (int i = 0; i <= haystack.Length - needle.Length; i++)
            {
                bool found = true;
                for (int j = 0; j < needle.Length; j++)
                {
                    if (haystack[i + j] != needle[j])
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                    return i;
            }
            return -1;
        }
    }
}
