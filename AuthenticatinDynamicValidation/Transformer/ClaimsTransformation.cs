using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using System.Linq;

namespace AuthenticatinDynamicValidation.Transformer
{
    public class ClaimsTransformation : IClaimsTransformation
    {
        public Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
        {
            var hasFriendClaim = principal.Claims.Any(o => o.Type == "Friend");

            if(!hasFriendClaim)
            {
                var claimIdentity = (ClaimsIdentity)principal.Identity;

                claimIdentity.AddClaim(new Claim("Friend", "Good"));
            }

            return Task.FromResult(principal);
        }
    }
}
