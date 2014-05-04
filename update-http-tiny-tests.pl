#!/usr/bin/env perl

use Cwd;
use File::Find;
use File::Path qw(make_path);
use File::Spec::Functions;
use File::Temp;

my $target_dir = shift or do {
    print STDERR "Usage: $0 {target-directory}\n";
    exit(1);
};

$target_dir = File::Spec->rel2abs($target_dir);

if (!-e $target_dir) {
    make_path($target_dir) or do {
        print STDERR "Failed to create the target directory\n";
        exit(1);
    };
}

# FIXME: Add warning when the target directory is not empty

my $oldcwd = getcwd;
my $dir = File::Temp->newdir;
chdir $dir;

unless (`git clone https://github.com/chansen/p5-http-tiny.git`) {
    print STDERR "Cloning the HTTP::Tiny Git repository failed\n";
    exit(1);
}

chdir 'p5-http-tiny/t';

find({
    wanted => sub {
        print "$File::Find::name\n";
        if (-d $File::Find::name) {
            make_path catfile($target_dir, $File::Find::name);
        }
        else {
            undef $/;
            open my $f, '<', $_;
            my $data = <$f>;
            close $f;
            
            if ($File::Find::name =~ /\.(pm|t|txt)$/) {
                $data =~ s/HTTP::Tiny(::Handle)?/HTTP::Tiny$1::SPDY/gs;
                $data =~ s/HTTP-Tiny/HTTP-Tiny-SPDY/gs;

                $data =~ s/^package t::/package t::http_tiny::/mg;
                $data =~ s/^use t::/use t::http_tiny::/mg;
                $data =~ s/t::(\w+)->new/t::http_tiny::$1->new/gs;

                $data =~ s{t/cases}{t/http_tiny/cases}gs;
            }

            open $f, '>', catfile($target_dir, $File::Find::name);
            print $f $data;
            close $f;
        }
    },
    no_chdir => 1
}, '.');

chdir $oldcwd;
