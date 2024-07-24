### Author:  Aaron W Morris <aaron@aarmor.net>
###
### This script allows integration of DUO directly into freeradius
###
### Optional:  Slack webhook for notifying when an authentication occurs
###            Slack communication occurs within a thread to prevent notification failures from affecting authentication


use Duo::API;
use Sys::Hostname;
use LWP::UserAgent;
use HTTP::Request;
use JSON;
use threads;
use Data::Dumper;
use strict;

# This is very important ! Without this script will not get the filled hashes from main.
use vars qw(%RAD_REQUEST %RAD_REPLY %RAD_CHECK);


my $DUO_IKEY = 'IIIIIIIIIIIIIIIIIIII';
my $DUO_SKEY = 'SSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSSS';
my $DUO_HOST = 'api-abcd1234.duosecurity.com';

my $SLACK_WEBHOOK_URL = 'https://slack_webhook_url';


#
# This the remapping of return values
#
use constant    RLM_MODULE_REJECT=>    0;#  /* immediately reject the request */
use constant    RLM_MODULE_FAIL=>      1;#  /* module failed, don't reply */
use constant    RLM_MODULE_OK=>        2;#  /* the module is OK, continue */
use constant    RLM_MODULE_HANDLED=>   3;#  /* the module handled the request, so stop. */
use constant    RLM_MODULE_INVALID=>   4;#  /* the module considers the request invalid. */
use constant    RLM_MODULE_USERLOCK=>  5;#  /* reject the request (user is locked out) */
use constant    RLM_MODULE_NOTFOUND=>  6;#  /* user not found */
use constant    RLM_MODULE_NOOP=>      7;#  /* module succeeded without doing anything */
use constant    RLM_MODULE_UPDATED=>   8;#  /* OK (pairs modified) */
use constant    RLM_MODULE_NUMCODES=>  9;#  /* How many return codes there are */



sub getDuoAuthClient {
    #&radiusd::radlog(0, "Setting up DUO API client");
    my $client = Duo::API->new($DUO_IKEY, $DUO_SKEY, $DUO_HOST);
    return $client;
}


# Function to handle authorize
sub authorize {
    # For debugging purposes only
#       &log_request_attributes;
#
    my $duo_username;
    if (length($RAD_REQUEST{'Stripped-User-Name'})) {
        $duo_username = $RAD_REQUEST{'Stripped-User-Name'};
    } else {
        $duo_username = $RAD_REQUEST{'User-Name'};
    };


    my $duo_preauth_params = {
        'username' => $duo_username,
    };

    my $duo = &getDuoAuthClient();
    my $res = $duo->json_api_call('POST',
                                  '/auth/v2/preauth',
                                  $duo_preauth_params);


    if ($res->{'result'} eq 'auth') {
        &radiusd::radlog(1, "DUO Auth enabled for " . $duo_username);

        # Add all devices to list for later reference
        $RAD_REQUEST{'Duo-User-Devices'} = [];
        foreach my $device (@{$res->{'devices'}}) {
            push(@{$RAD_REQUEST{'Duo-User-Devices'}}, $device->{'device'});
        }

        return RLM_MODULE_OK;

    } elsif ($res->{'result'} eq 'allow') {
        # 2FA bypass enabled
        &radiusd::radlog(1, "DUO Auth 2FA bypass enabled for " . $duo_username);
        $RAD_REQUEST{'Duo-2fa-Bypass'} = 'bypass';
        return RLM_MODULE_OK;
    }


    &radiusd::radlog(1, "DUO Auth problem for " . $duo_username . ": " . $res->{'status_msg'});
    #&radiusd::radlog(1, $res->{'result'});

    #my $slack_thread = threads->create(\&slack_notify, "DUO Auth problem for " . $duo_username . " on " . hostname() . ": " . $res->{'status_msg'});
    #$slack_thread->detach();

    return RLM_MODULE_REJECT;
}

# Function to handle authenticate
sub authenticate {
    # For debugging purposes only
    #&log_request_attributes;

    if (length($RAD_REQUEST{'Duo-2fa-Bypass'})) {
        if ($RAD_REQUEST{'Duo-2fa-Bypass'} eq 'bypass') {
            &radiusd::radlog(1, "*** DUO bypass enabled ***");
            return RLM_MODULE_OK;
        };
    };


    my $duo_username;
    if (length($RAD_REQUEST{'Stripped-User-Name'})) {
        $duo_username = $RAD_REQUEST{'Stripped-User-Name'};
    } else {
        $duo_username = $RAD_REQUEST{'User-Name'};
    };


    my $duo_auth_params = {
        'username' => $duo_username,
    };

    if (length($RAD_REQUEST{'User-Password-Otp'})) {
	if ($RAD_REQUEST{'User-Password-Otp'} =~ /^phone(\d*)$/) {
	    &radiusd::radlog(1, "Using DUO phone method");
        my $device = &getDuoDevice($1);

	    $duo_auth_params->{'factor'} = 'phone';
	    $duo_auth_params->{'device'} = $device;
	} elsif ($RAD_REQUEST{'User-Password-Otp'} =~ /^sms(\d*)$/) {
	    &radiusd::radlog(1, "Using DUO sms method");
        my $device = &getDuoDevice($1);

	    $duo_auth_params->{'factor'} = 'sms';
	    $duo_auth_params->{'device'} = $device;
	} elsif ($RAD_REQUEST{'User-Password-Otp'} =~ /^push(\d*)$/) {
	    &radiusd::radlog(1, "Using DUO push method");
        my $device = &getDuoDevice($1);

	    $duo_auth_params->{'factor'} = 'push';
	    $duo_auth_params->{'device'} = $device;
	} else {
	    &radiusd::radlog(1, "Using DUO pincode method");

	    $duo_auth_params->{'factor'} = 'passcode';
	    $duo_auth_params->{'passcode'} = $RAD_REQUEST{'User-Password-Otp'};
	};
    } else {
        &radiusd::radlog(1, "Using DUO auto (default) method");

        $duo_auth_params->{'factor'} = 'auto';
        $duo_auth_params->{'device'} = 'auto';
    };

    #print Dumper($duo_auth_params);

    #&radiusd::radlog(0, "Starting DUO API auth call");
   
    my $duo = &getDuoAuthClient();
    my $res = $duo->json_api_call('POST',
                                  '/auth/v2/auth',
                                  $duo_auth_params);

    #&radiusd::radlog(1, "DUO API auth call complete");
    #&radiusd::radlog(1, Dumper($res));

    if ($res->{'result'} eq 'allow') {
        #print "DUO Success";
        &radiusd::radlog(1, "DUO Auth Successful for " . $duo_username);
        #&radiusd::radlog(1, $res->{'result'});

        #my $slack_thread = threads->create(\&slack_notify, "DUO Auth Successful for " . $duo_username . " using " . $duo_auth_params->{'factor'} . " factor on " . hostname());
        #$slack_thread->detach();

        return RLM_MODULE_OK;
    };


    &radiusd::radlog(1, "DUO Auth Failure for " . $duo_username . ": " . $res->{'status_msg'});

    #my $slack_thread = threads->create(\&slack_notify, "DUO Auth Failure for " . $duo_username . " using " . $duo_auth_params->{'factor'} . " factor on " . hostname() . ": " . $res->{'status_msg'});
    #$slack_thread->detach();

    return RLM_MODULE_REJECT;
}

# Function to handle preacct
sub preacct {
    # For debugging purposes only
#       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle accounting
sub accounting {
    # For debugging purposes only
#       &log_request_attributes;

    # You can call another subroutine from here
    #&test_call;

    return RLM_MODULE_OK;
}

# Function to handle checksimul
sub checksimul {
    # For debugging purposes only
#       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle pre_proxy
sub pre_proxy {
    # For debugging purposes only
#       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle post_proxy
sub post_proxy {
    # For debugging purposes only
#       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle post_auth
sub post_auth {
    # For debugging purposes only
#       &log_request_attributes;

    return RLM_MODULE_OK;
}

# Function to handle xlat
sub xlat {
    # For debugging purposes only
#       &log_request_attributes;

    # Loads some external perl and evaluate it
    my ($filename,$a,$b,$c,$d) = @_;
    &radiusd::radlog(1, "From xlat $filename ");
    &radiusd::radlog(1,"From xlat $a $b $c $d ");
    local *FH;
    open FH, $filename or die "open '$filename' $!";
    local($/) = undef;
    my $sub = <FH>;
    close FH;
    my $eval = qq{ sub handler{ $sub;} };
    eval $eval;
    eval {main->handler;};
}

# Function to handle detach
sub detach {
    # For debugging purposes only
#       &log_request_attributes;

    # Do some logging.
    &radiusd::radlog(0,"rlm_perl::Detaching. Reloading. Done.");
}

#
# Some functions that can be called from other functions
#

sub test_call {
    # Some code goes here
}


sub log_request_attributes {
    # This shouldn't be done in production environments!
    # This is only meant for debugging!
    for (keys %RAD_REQUEST) {
            &radiusd::radlog(1, "RAD_REQUEST: $_ = $RAD_REQUEST{$_}");
    }
}


sub getDuoDevice {
    my ($i) = @_;

    # return auto when no index is passed, or 0
    if (!$i) {
        &radiusd::radlog(1, "Using 'auto' device for DUO");
        return('auto');
    }


    # convert to array index
    my $idx = int($i) - 1;

    if (ref($RAD_REQUEST{'Duo-User-Devices'}) eq 'SCALAR') {
        my $device = $RAD_REQUEST{'Duo-User-Devices'};

        &radiusd::radlog(1, "Using " . $device . " for DUO");
        return($RAD_REQUEST{'Duo-User-Devices'});

    } elsif(ref($RAD_REQUEST{'Duo-User-Devices'}) eq 'ARRAY') {
        # if index is empty, just use auto
        if (!$RAD_REQUEST{'Duo-User-Devices'}[$idx]) {
            &radiusd::radlog(1, "No such device, using 'auto' device for DUO");
            return('auto');
        }

        my $device = $RAD_REQUEST{'Duo-User-Devices'}[$idx];

        &radiusd::radlog(1, "Using " . $device . " for DUO");
        return($device);
    }


    # Failsafe
    &radiusd::radlog(1, "Failsafe, using 'auto' device for DUO");
    return('auto');
}


sub slack_notify {
    my ($message) = @_;

    my $json = JSON->new;
    my $json_data = {
        'text' => $message,
    };

    my $req = HTTP::Request->new('POST', $SLACK_WEBHOOK_URL);
    $req->header('Content-Type' => 'application/json');
    $req->content($json->encode($json_data));

    my $lwp = LWP::UserAgent->new(timeout=>3);
    $lwp->request($req);
}
