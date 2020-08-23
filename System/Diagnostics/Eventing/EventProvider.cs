// Author: Ryan Cobb (@cobbr_io)
// Project: SharpSploit (https://github.com/cobbr/SharpSploit)
// License: BSD 3-Clause

namespace System.Diagnostics.Eventing
{
    internal class EventProvider
    {
        private Guid guid;

        public EventProvider(Guid guid)
        {
            this.guid = guid;
        }
    }
}