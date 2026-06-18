// Copyright 2022 hev, r@hev.cc
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cmd

import (
	"context"
	"encoding/base64"
	"net"
	"strconv"
	"time"
	"go.uber.org/zap"
)

func lookupIP4P(addr string, portStr string) (*net.UDPAddr, error) {
	pureGoResolver := &net.Resolver{
		PreferGo: true,
	}
	// 为 TXT 解析设置一个合理的独立超时，防止无限死等
	txtCtx, txtCancel := context.WithTimeout(context.Background(), 3*time.Second)
	logger.Info("try TXT record", zap.String("addr", addr))
	addrs, err := pureGoResolver.LookupTXT(txtCtx, addr)
	defer txtCancel()

	if err == nil {
		for _, addr_64 := range addrs {
			decodeBytes, err := base64.StdEncoding.DecodeString(addr_64)
			if err != nil {
				continue
			}
			addr_s, port_s, _ := net.SplitHostPort(string(decodeBytes))
			port_i, err := strconv.Atoi(port_s)
			if err != nil {
				continue
			}
			return &net.UDPAddr{
				IP:   net.ParseIP(addr_s),
				Port: port_i,
			}, nil
		}
	}

	// TXT 失败，进入 IP4P 解析
	logger.Warn("try TXT record failed, try ip4p then", zap.String("addr", addr))
	
	// 为 IP 解析设置独立的 3 秒超时
	ipCtx, ipCancel := context.WithTimeout(context.Background(), 3*time.Second)
	ips, err := pureGoResolver.LookupIP(ipCtx, "ip6", addr)
	defer ipCancel()

	if err == nil {
		for _, ip := range ips {
			// 1. 安全转换：确保一定是 16 字节的 IPv6 格式
			ipv6 := ip.To16()
			if ipv6 == nil {
				continue
			}
			
			// 2. 匹配 Teredo / IP4P 前缀 (2001:0000::/32)
			if ipv6[0] == 0x20 && ipv6[1] == 0x01 && ipv6[2] == 0x00 && ipv6[3] == 0x00 {
				// 3. 提取内嵌的 IPv4（使用局部变量，不污染入参 addr）
				targetIP := net.IPv4(ipv6[12], ipv6[13], ipv6[14], ipv6[15])
				port := int(ipv6[10])<<8 | int(ipv6[11])
				
				return &net.UDPAddr{
					IP:   targetIP,
					Port: port,
				}, nil
			}
		}
	}

	// 最终降级：普通 UDP 解析模式
	logger.Warn("try ip4p record failed, try normal mode", zap.String("addr", addr))
	hostPort := net.JoinHostPort(addr, portStr)
	normalAddr, err := net.ResolveUDPAddr("udp", hostPort)
	if err != nil {
		return nil, err
	}
	return normalAddr, nil
}

