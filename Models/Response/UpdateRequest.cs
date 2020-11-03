using System.ComponentModel.DataAnnotations;
using ServerAPI.Entities;

namespace ServerAPI.Models.Response
{
    public class UpdateRequest
    {
        private string _password;
        private string _role;
        private string _email;
        
       
        [Required]
        public string UserName { get; set; }
        [EnumDataType(typeof(Role))]
        public string Role
        {
            get => _role;
            set => _role = replaceEmptyWithNull(value);
        }

        [EmailAddress]
        public string Email
        {
            get => _email;
            set => _email = replaceEmptyWithNull(value);
        }

        [MinLength(6)]
        public string Password
        {
            get => _password;
            set => _password = replaceEmptyWithNull(value);
        }

     

        // helpers

        private string replaceEmptyWithNull(string value)
        {
            // replace empty string with null to make field optional
            return string.IsNullOrEmpty(value) ? null : value;
        }
    }
}