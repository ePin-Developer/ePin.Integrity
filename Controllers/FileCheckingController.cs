using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc;
using System.Numerics;
using Newtonsoft.Json;
using Microsoft.Extensions.Options;
using Core;
using System.Text;
using System.Linq;
using DataAccess.Models;

namespace ePin.IntegrityMonitor.Controllers
{
    public class FileCheckingController : Controller
    {
        private IHostingEnvironment _hostingEnvironment;
        private readonly Configurations _configurations;

        public FileCheckingController(IOptionsSnapshot<Configurations> optionsConfigurations, IHostingEnvironment hostingEnvironment)
        {
            _hostingEnvironment = hostingEnvironment;
            _configurations = optionsConfigurations.Value;
        }

        #region Actions

        [HttpGet("/")]
        [HttpGet("/GetFilesStructure")]
        public IActionResult Index()
        {
            var model = new IntegrityModel();
            model.Challenge = GetUniqueKey(32);
            TempData["Challenge"] = model.Challenge;
            return View("Index", model);
        }

        [HttpPost("/")]
        public JsonResult GetFilesHashing(string jsonFileList, string signature, string challenge)
        {
            IList<FileIntegrity> fileIntegrityList = JsonConvert.DeserializeObject<IList<FileIntegrity>>(jsonFileList);

            var challengeSession = TempData["Challenge"].ToString();

            if (string.Equals(challengeSession, challenge, StringComparison.OrdinalIgnoreCase))
            {
                bool isSignatureValid = ECKey.ValidECDSASignature(signature, challengeSession, _configurations.ClientPublicKeyECDSA);
                if (isSignatureValid)
                {
                    for (var i = 0; i < fileIntegrityList.Count; i++)
                    {
                        fileIntegrityList[i] = HashFile(fileIntegrityList[i]);
                    }
                    return new JsonResult(fileIntegrityList);
                }
            }
            return new JsonResult("");
        }

        [HttpPost("/GetFilesStructure/{signature}/{searchPattern}")]
        [HttpPost("/GetFilesStructure")]
        public JsonResult GetFilesStructure(string searchPattern, string signature, string challenge)
        {
            try
            {
                var challengeSession = TempData["challenge"].ToString();
                IList<FileIntegrity> FileIntegrityList = new List<FileIntegrity>();

                if (string.Equals(challengeSession, challenge, StringComparison.OrdinalIgnoreCase))
                {
                    bool isSignatureValid = ECKey.ValidECDSASignature(signature, challengeSession, _configurations.ClientPublicKeyECDSA);
                    if (isSignatureValid)
                    {
                        var settingsSiteFolder = Path.Combine(_hostingEnvironment.ContentRootPath, "..");
                        var fileListIEnumerable = GetFilesDirectory(settingsSiteFolder, searchPattern);
                        string[] fileList = fileListIEnumerable.ToArray();

                        if (fileList?.Length > 0)
                        {
                            for (var i = 0; i < fileList.Length - 1; i++)
                            {
                                FileIntegrity file = new FileIntegrity();
                                file.Filename = fileList[i];
                                file = HashFile(file);
                                FileIntegrityList.Add(file);
                            }
                        }
                    }
                }

                var json = new JsonResult(FileIntegrityList);
                return json;
            }
            catch (Exception e)
            {
                Console.WriteLine(e.ToString());
            }
            return null;
        }

        [HttpGet("/GetECDSA")]
        public IActionResult GetECDSA()
        {
            var model = new IntegrityModel();
            model.PrivateKeyBase64 = ECKey.GenerateKeyIntPrivateKey();
            model.PublicKeyBase64 = ECKey.GetPublicKeyFromPrivateKeyEx(Base64Decode(model.PrivateKeyBase64));
            var messageBase64 = Base64Encode(GetUniqueKey(32));
            var privateKey = BigInteger.Parse(Base64Decode(model.PrivateKeyBase64));
            var signature = ECKey.GenerateECDSASignature(messageBase64, privateKey.ToString());
            model.Verified = ECKey.ValidECDSASignature(signature, messageBase64, model.PublicKeyBase64).ToString();
            return View("GetECDSA", model);
        }

        #endregion Actions

        #region Helpers

        internal static readonly char[] AvailableCharacters = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M',
            'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
          };

        private static IEnumerable<string> GetFilesDirectory(string root, string searchPattern)
        {
            Stack<string> pending = new Stack<string>();
            pending.Push(root);
            while (pending.Count != 0)
            {
                var path = pending.Pop();
                string[] next = null;
                try
                {
                    next = Directory.GetFiles(path, searchPattern);
                }
                catch { }
                if (next != null && next.Length != 0)
                    foreach (var file in next) yield return file;
                try
                {
                    next = Directory.GetDirectories(path);
                    foreach (var subdir in next) pending.Push(subdir);
                }
                catch { }
            }
        }

        private FileIntegrity HashFile(FileIntegrity file)
        {
            try
            {
                //Create object of FileInfo for specified path
                FileInfo fi = new FileInfo(file.Filename);
                if (!fi.Exists)
                {
                    file.ErrorMessage = "Filename: " + file.Filename + " was not found";
                    return file;
                }

                //Open file for Read
                FileStream fs = fi.Open(FileMode.Open, FileAccess.Read);

                file.CreationDateTime = fi.CreationTimeUtc.ToString("MM-dd-yyyy HH:mm");
                using (HashAlgorithm hashAlgorithm = SHA256.Create())
                {
                    byte[] hash = hashAlgorithm.ComputeHash(fs);
                    file.ResponseHashed = Convert.ToBase64String(hash);
                }
                fs.Close();
            }
            catch (Exception e)
            {
                file.ErrorMessage = e.StackTrace + e.ToString();
            }
            return file;
        }

        public static string GetUniqueKey(int maxSize)
        {
            char[] chars = new char[62];
            chars = AvailableCharacters;
            byte[] data = new byte[1];
            using (RNGCryptoServiceProvider crypto = new RNGCryptoServiceProvider())
            {
                crypto.GetNonZeroBytes(data);
                data = new byte[maxSize];
                crypto.GetNonZeroBytes(data);
            }
            StringBuilder result = new StringBuilder(maxSize);
            foreach (byte b in data)
            {
                result.Append(chars[b % (chars.Length)]);
            }
            return result.ToString();
        }

        public static string Base64Decode(string base64EncodedData)
        {
            var base64EncodedBytes = System.Convert.FromBase64String(base64EncodedData);
            return System.Text.Encoding.UTF8.GetString(base64EncodedBytes);
        }

        public static string Base64Encode(string plainText)
        {
            var plainTextBytes = System.Text.Encoding.UTF8.GetBytes(plainText);
            return System.Convert.ToBase64String(plainTextBytes);
        }

        #endregion Helpers
    }
}