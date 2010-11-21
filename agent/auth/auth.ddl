metadata    :name        => "SimpleRPC Scan Auth.log Agent",
            :description => "An agent that scans auth.log for failed attempts",
            :author      => "Anton Lindstrom",
            :license     => "GPLv2",
            :version     => "0.1",
            :url         => "http://github.com/antonlindstrom/",
            :timeout     => 10


["internal", "external"].each do |act|
    action act, :description => "List invalid authentication attempts for #{act} IPs" do
        
           output :output,
               :description => "Output a list of IPs and number of attempts",
               :display_as  => "List"
    end
end

action "threshold", :description => "List IPs that have reached a failed attempt number of [value]" do
    display :always

    input :tvalue, 
          :prompt      => "Threshold value",
          :description => "The threshold value that the failed auth attempts is over.",
          :type        => :integer,
          :validation  => '^\d+$',
          :optional    => false,
          :maxlength   => 5

    output :output,
           :description => "Output a list of IPs and number of attempts",
           :display_as  => "List"
end
