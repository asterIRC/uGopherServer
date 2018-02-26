#!/usr/local/bin/tclsh8.6

# welcome to the cringeball proxy

if {0} {
uGopherServer - The Universal Gopher Server
clientproxy.tcl - a ... client? to the universal gopher server
Copyright (c) 2018- Ellenor/Reinhilde Malik <ellenor@umbrellix.net>
(our legal name is Jack Johnson, but don't tell anyone we're trans, haha)

This program is distributed as part of a derivative work of:
Gophernicus - Copyright (c) 2009-2014 Kim Holviala <kim@holviala.com>
and is thus subject to its copyright.
All rights reserved in theory, in practice very few.

Gophernicus - Copyright (c) 2009-2014 Kim Holviala <kim@holviala.com>
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


}

package require tls

if {[llength $::argv] < 2} {
	puts stdout "Oi, you gotta specify both the port AND the hostname - try: ./${argv0} 27070 127.0.0.1"
	exit
}
socket -myaddr [lindex $::argv 1] -server acceptconn [lindex $::argv 0]
set proxyhost [lindex $::argv 1]

proc acceptconn {c a p} {
	#puts stdout "received connection from 1/$p/$a"
	chan configure $c -blocking 0 -buffering line -translation {auto crlf}
	chan event $c readable [list tgp:read $c $a $p]
}

set proxify [list 0 0]

proc tgp:fmt-line {type selector path host {port 70} {plus {}}} {
	if {$plus == {}} {set tabs ""} {set tabs "\x09"}
	format "%s%s\x09%s\x09%s\x09%s%s%s" $type $selector $path $host $port $tabs $plus
}

proc tgp:read {c a p} {
	set gotten [gets $c line]
	#puts stdout $line
	if {[string index $line 0] == "/"} {set line [string range $line 1 end]}
	set req [split $line "/"]
	if {[llength $req] < 3} {
		puts $c [tgp:fmt-line 3 "Error: insufficient path length" "/" [lindex $::argv 1] [lindex $::argv 0]]
		close $c
		return
	}
	#puts stdout $req
	set sendsel [lassign $req stype tp ta]
	set socketc ::socket
	if {[llength $sendsel] > 0 || ([lindex $sendsel 0] != {} && [lindex $sendsel 0] != "")} {set sendsel [join $sendsel "/"]} {set sendsel ""}
	if {[string length $stype] > 1} {
		set stype [string index $stype 0]
		set socketc [list ::tls::socket -require 0]
	}
	if {$tp > 100000} {
		set tp [expr {$tp - 100000}]
		set socketc [list ::tls::socket -require 0]
	}
	if {$stype == "1" || $stype == "7"} {
		set socketrcb tgp:smread
	} elseif {$stype == "0" || $stype == "6"} {
		set socketrcb tgp:stread
	} else {
		set socketrcb tgp:sbread
	}
	if {[set errval [catch [list {*}$socketc $ta $tp] err]] != 0} {
		puts $c [tgp:fmt-line 3 "Error: connection did not synchronise" "/" "127.0.0.1" [lindex $::argv 0]]
		#puts stdout [format "%s/%s %s;%s/%s %s %s - failed" $p $a $ta $tp $stype $sendsel $socketc]
		close $c
		return
	} {
		chan configure $err -blocking 0 -buffering line -buffersize 64
		puts $err $sendsel
		#puts stdout [format "%s/%s %s;%s/%s %s %s - fetching" $p $a $ta $tp $stype $sendsel $socketrcb]
		#chan event $c readable [list tgp:getitinthere $err $c]
		chan event $err readable [list $socketrcb $c $err]
		return
	}
}

proc tgp:stread {channel fp} {
	fconfigure $channel -translation {auto crlf} -buffering line -buffersize 128
	while {[string length [set text [read $fp 2048]]] > 0} {
		puts $channel $text
		flush $channel
	}
	flush $channel
	if {[fblocked $fp] == 0} {close $fp; close $channel}
}

proc tgp:sbread {channel fp} {
	fconfigure $channel -translation binary -buffering full -buffersize 128
	while {[string length [set text [read $fp 2048]]] > 0} {
		puts $channel $text
	}
	flush $channel
	if {[fblocked $fp] == 0} {close $fp; close $channel}
}

proc tgp:getitinthere {channel fp} {
	fconfigure $channel -translation binary -buffering none
	while {[string length [set text [read $fp 2048]]] > 0} {
		puts -nonewline $channel $text
	}
	flush $channel
	if {[fblocked $fp] == 0} {close $fp; close $channel}
	if {[fblocked $channel] == 0} {close $fp; close $channel}
}

proc tgd:split {line} {
	set mapping [split $line "\x09"]
	set stype [string index [lindex $mapping 0] 0]
	set sname [string range [lindex $mapping 0] 1 end]
	set output [list $stype $sname]
	foreach {x} [lrange $mapping 1 end] {
		lappend output $x
	}
	return $output
}


proc tgp:smread {channel fp} {
	if {[catch [list chan tell $channel] err] != 0} {
		close $fp
	}
	if {[catch [list chan tell $fp] err] != 0} {
		close $channel
	}
	fconfigure $channel -translation {auto crlf} -buffering line -buffersize 2048
	fconfigure $fp -translation {auto crlf} -buffering line -buffersize 2048
	while {[gets $fp text] > 0} {
		set gopherplus [lassign [tgd:split $text] st sn ts ta tp]
		#puts stdout [format "/%s/ -> g+/%s/ st/%s/ sn/%s/ ts/%s/ ta/%s/ tp/%s/" $text $gopherplus $st $sn $ts $ta $tp]
		if {$st != "i" && $st != "."} {
			if {$tp > 100000} {
				set iss "t"
				set tp [expr {$tp - 100000}]
			} {set iss ""}
			set ts [format "/%s%s/%s/%s/%s" $st $iss $tp $ta $ts]
			set ta $::proxyhost
			set tp [lindex $::argv 0]
			if {[llength $gopherplus] == 0} {set otext [tgp:fmt-line $st $sn $ts $ta $tp]} {
				set otext [tgp:fmt-line $st $sn $ts $ta $tp [join $gopherplus "\x09"]]
			}
		} {
			set otext $text
		}
		puts $channel $otext
	}
	flush $channel
	if {[fblocked $fp] == 0} {close $fp; close $channel}
}

vwait forever
