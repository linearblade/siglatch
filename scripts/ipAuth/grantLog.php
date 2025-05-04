<?php

function grantAccessLog($ip, $user, $comment, $actionCode, $actionName, $payloadBase64) {
    $log = [];

    // Validate and process the comment
    $isAscii = mb_check_encoding($comment, 'ASCII');
    $isNullTerminated = substr($comment, -1) === "\0";
    $unicode = false;
    $b64 = false;

    if ($comment === "") {
        $comment = "\0";
    } elseif (!$isAscii) {
        $comment = base64_encode($comment);
        $unicode = true;
        $b64 = true;
    } elseif (!$isNullTerminated) {
        $comment .= "\0";
    }

    $log['ip'] = $ip;
    $log['user'] = $user;
    $log['comment'] = $comment;
    $log['timestamp'] = date('c');  // ISO 8601 format
    $log['b64'] = $b64;
    if ($unicode) {
        $log['unicode'] = true;
    }

    // Example logging (append to a file)
    $logfile = '/var/log/access_log.jsonl';  // Change path as needed
    file_put_contents($logfile, json_encode($log, JSON_UNESCAPED_SLASHES) . PHP_EOL, FILE_APPEND);
}