(defpackage :net
  (:use :common-lisp))

(in-package :net)


;;;; Utilities
;;;
;;;
;;; 


(deftype octet () '(unsigned-byte 8))

(defgeneric sizeof (s))

(defun u8 (buff n)
  (elt buff n))

(defun u16 (buff n)
  (logior (ash (elt buff n) 8) (elt buff (+ n 1))))



;;; TUN/TAP Devices
;;;
;;; On Linux, TUN/TAP allows user-space programs to register virtual
;;; network devices that will handle Ethernet or IP transmissions,
;;; respectively. For more information, read the kernel documentation
;;; at:
;;; 
;;;    https://www.kernel.org/doc/Documentation/networking/tuntap.txt

;;; Some constants used to allocate a TUN device. You can find their
;;; values in the header file /usr/include/linux/if_tun.h.

(defconstant TUNSETIFF      #x400454ca)
(defconstant TUNSETOWNER    (+ TUNSETIFF 2))
(defconstant IFF-TUN        #x0001)
(defconstant IFF-TAP        #x0002)
(defconstant IFF-NO-PI      #x1000)

;;; ifreq structure, as defined in /usr/include/linux/if.h

(sb-alien:define-alien-type ifreq
    (sb-alien:struct ifreq
                     (ifrn-name (sb-alien:array sb-alien:char 16))
                     (ifru-flags sb-alien:short)))

;; Create stream from file descriptor

;;
;; (sb-sys:make-fd-stream )

(defun alloc-tun ()
  (let ((fd (sb-posix:open "/dev/net/tun" sb-posix:o-rdwr)))
    (sb-alien:with-alien ((req ifreq))
      (let ((name (sb-alien:slot req 'ifrn-name)))
        (loop
           for i from 0
           for ch across (sb-ext:string-to-octets "taplisp" :null-terminate t)
           do (setf (sb-alien:deref name i) ch)))
      (setf (sb-alien:slot req 'ifru-flags) (logior IFF-TUN IFF-NO-PI))
      (sb-posix:ioctl fd TUNSETIFF (sb-alien:addr req))
      (sb-sys:make-fd-stream fd :input t :output t :element-type 'octet :auto-close t))))


(defvar *if*
  (alloc-tun))


(defun drain ()
  "Consume all data available in the interface."
  (loop while (listen *if*) do (read-byte *if*)))




;;;; IP: RFC791
;;;
;;; 
;;;    0                   1                   2                   3
;;;      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
;;;     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;;;     |Version|  IHL  |Type of Service|          Total Length         |
;;;     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;;;     |         Identification        |Flags|      Fragment Offset    |
;;;     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;;;     |  Time to Live |    Protocol   |         Header Checksum       |
;;;     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;;;     |                       Source Address                          |
;;;     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;;;     |                    Destination Address                        |
;;;     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
;;;     |                    Options                    |    Padding    |
;;;     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

(defclass ip-headers ()
  ((version
    :initarg :version
    :accessor ip-version)
   (ihl
    :initarg :ihl
    :accessor ip-ihl)
   (dscp
    :initarg :dscp
    :accessor ip-dscp)
   (ecn
    :initarg :ecn
    :accessor ip-ecn)
   (length
    :initarg :length
    :accessor ip-length)
   (identification
    :initarg :identification
    :accessor ip-identification)
   (flags
    :initarg :flags
    :accessor ip-flags)
   (fragment-offset
    :initarg :fragment-offset
    :accessor ip-fragment-offset)
   (ttl
    :initarg :ttl
    :accessor ip-ttl)
   (protocol
    :initarg :protocol
    :accessor ip-protocol)
   (checksum
    :initarg :checksum
    :accessor ip-checksum)
   (source
    :initarg :source
    :accessor ip-source)
   (destination
    :initarg :destination
    :accessor ip-destination)
   (options
    :initarg :options
    :accessor ip-options)))


(defmethod sizeof ((ip ip-headers))
  (* (ip-ihl ip) 4))


(defvar *ip-protocols*
  ;; Hex    Keyword     Protocol                                    References
  '((#x01   :ICMP       #| Internet Control Message Protocol        RFC 792     |#)
    (#x02   :IGMP       #| Internet Group Management Protocol       RFC 1112    |#)
    (#x06   :TCP        #| Transmission Control Protocol            RFC 793     |#)
    (#x11   :UDP        #| User Datagram Protocol                   RFC 768     |#)))


(defun read-ip-headers ()
  "Read IPv4 headers"
  (let ((buff (make-array 60 :element-type 'octet))
        (minheaders-length 20))
    
    ;; Read mandatory headers
    (read-sequence buff *if* :end minheaders-length)
    (let* ((ihl (ldb (byte 4 0) (u8 buff 0)))
           (headers-length (* ihl 4))
           (options-length (- headers-length minheaders-length)))
      ;; Read options
      (read-sequence buff *if*
                     :start minheaders-length
                     :end (+ minheaders-length options-length))
      
      (make-instance 'ip-headers
                     :version (ldb (byte 4 4) (u8 buff 0))
                     :ihl ihl     
                     :dscp (ldb (byte 6 2) (u8 buff 1))
                     :ecn (ldb (byte 2 0) (u8 buff 1))
                     :length (u16 buff 2)
                     :identification (u16 buff 4)
                     ;; flags
                     ;; fragment
                     :ttl (u8 buff 8)
                     :protocol (second (find (u8 buff 9) *ip-protocols* :key #'first))
                     :checksum (u16 buff 10)
                     :source (vector (elt buff 12) (elt buff 13) (elt buff 14) (elt buff 15))
                     :destination (vector (elt buff 16) (elt buff 17) (elt buff 18) (elt buff 19))
                     :options (subseq buff minheaders-length (+ minheaders-length options-length))))))


(defun read-ip-packet ()
  "Read a IPv4 package"
  (let* ((headers (read-ip-headers))
         (data-length (- (ip-length headers) (sizeof headers)))
         (data (make-array data-length :element-type 'octet)))
    (read-sequence data *if*)
    (values data headers)))



;;;; UDP: RFC768
;;; 
;;; 
;;; Headers format:
;;; 
;;;      0      7 8     15 16    23 24    31
;;;     +--------+--------+--------+--------+
;;;     |     Source      |   Destination   |
;;;     |      Port       |      Port       |
;;;     +--------+--------+--------+--------+
;;;     |                 |                 |
;;;     |     Length      |    Checksum     |
;;;     +--------+--------+--------+--------+
;;;     |
;;;     |          data octets ...
;;;     +---------------- ...
;;; 
;;; 

(defclass udp-headers ()
  ((source-port
    :initarg :source-port
    :accessor udp-source-port)
   (destination-port
    :initarg :destination-port
    :accessor udp-destination-port)
   (length
    :initarg :length
    :accessor udp-length)
   (checksum
    :initarg :checksum
    :accessor udp-checksum)))


(defmethod sizeof ((udp udp-headers))
  8)


(defun parse-udp-packet (data)
  (let ((headers (make-instance 'udp-headers)))
    (setf (udp-source-port headers) (u16 data 0)
          (udp-destination-port headers) (u16 data 2)
          (udp-length headers) (u16 data 4)
          (udp-checksum headers) (u16 data 6))
    (values (subseq data (sizeof headers) (udp-length headers))
            headers)))
