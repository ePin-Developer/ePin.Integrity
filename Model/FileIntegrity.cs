using Newtonsoft.Json;

namespace DataAccess.Models
{
    public partial class FileIntegrity
    {
        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string Filename { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string ResponseHashed { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string MonitorHashed { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string CreationDateTime { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string PublisherInformation { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string ValidFrom { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string ValidTo { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string IssuedBy { get; set; }

        [JsonProperty(NullValueHandling = NullValueHandling.Ignore)]
        public string ErrorMessage { get; set; }
    }
}