using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace ServerAPI.Models.Response
{
	public class OrderResponse
	{              
        public string CustomerId { get; set; }
        public int EmployeeId { get; set; }              
        public string ShipCountry { get; set; }      
    }
}
