metadata    :name        => "SimpleRPC Scan Auth.log Agent",
            :description => "An agent that scans auth.log for failed attempts",
            :author      => "Anton Lindstrom",
            :license     => "GPLv2",
            :version     => "0.1",
            :url         => "http://github.com/antonlindstrom/",
            :timeout     => 10


["internal", "external"].each do |act|
    action act, :description => "List invalid authentication attempts for #{act} IPs" do
    display :always
        
    output :ip,
           :description => "List of IPs that have tried to scan",
           :display_as  => "IP Address"
    output :num_attempts,
           :description => "Number of entries in auth.log",
           :display_as  => "Number of scans"
    end
end

action "threshold", :description => "List IPs that have reached a failed attempt number of [value]" do
    display :always

    input :tvalue, 
          :prompt      => "Threshold value",
          :description => "The threshold value that the failed auth attempts is over.",
          :type        => :string,
          :validation  => '^\d+$',
          :optional    => false,
          :maxlength   => 5

    output :ip,
          :description => "List of IPs that have tried to scan",
          :display_as  => "IP Address"
    output :num_attempts,
          :description => "Number of entries in auth.log",
          :display_as  => "Number of scans"

end
