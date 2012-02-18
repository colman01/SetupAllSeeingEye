//
//  PTXASIS3Request.m
//  pocketTaxi
//
//  This class should subclass the existing solution in
//  ASI3Request for the PTX server, to complete login
//  Created by Colman Marcus-Quinn on 02.01.12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import "PTXASIS3Request.h"

@implementation PTXASIS3Request

+ (NSData *)signedString:(NSString *)secretKey signString:(NSString *)stringToSign
{
    const char *strBytes = (const char*)[stringToSign UTF8String];
    unsigned char hmac_buffer[CC_SHA256_DIGEST_LENGTH];
    
    bzero(hmac_buffer, CC_SHA256_DIGEST_LENGTH);
    
    const char *keyBytes = (const char*)[secretKey UTF8String];
    
    CCHmac(kCCHmacAlgSHA256, keyBytes, strlen(keyBytes), strBytes, strlen(strBytes), hmac_buffer);
    
    NSData *signedData = [NSData dataWithBytes:hmac_buffer length:CC_SHA256_DIGEST_LENGTH];
    
    return signedData;
}

- (NSString *)stringToSignForHeaders
{
    NSString *contentMD5 = @"";
    NSString *body = [[NSString alloc] initWithData:self.postBody encoding:self.responseEncoding];
    //NSString *body = [NSString stringWithUTF8String:[self.postBody bytes]];
    
    if ([contentType isEqualToString:@"multipart/form-data"]) {
        //        NSString *signature = [ASIHTTPRequest base64forData:[ASIS3Request signedString:[self secretAccessKey] signString:stringToSign]];
        //        body = [Base64 encode:self.postBody];
        body = [ASIHTTPRequest base64forData:self.postBody];
        if ([body length] > 0) {
            contentMD5 = @""; 
            //contentMD5 = body; 
            //[HTTPRequest MD5WithString:[NSString stringWithUTF8String:[body cStringUsingEncoding:[NSString defaultCStringEncoding]]]];
        }
    }
    else {
        if ([body length] > 0) {
            //contentMD5 = [HTTPRequest MD5WithString:[NSString stringWithUTF8String:[body cStringUsingEncoding:[NSString defaultCStringEncoding]]]];
            contentMD5 = [ASIHTTPRequest MD5WithString:body];
        }            
    }
    
    
    NSString *stringToSign = [NSString stringWithFormat:@"%@\n\n\n%@\n%@", requestMethod,dateString,[self uri]];
    
    NSData *signatures = [ASIS3Request signedString:[pocketTaxiAppDelegate getSecretAccessKey] signString:stringToSign];
    NSString * base64Request = [self base64:signatures];
    NSString * base64Lib = [ASIHTTPRequest base64forData:signatures];
    // This is the Authorization header that must be added to the HTTP request
    //    NSString *authHeader = [NSString stringWithFormat:@"PTX %@:%@", accessKey, [ASIHTTPRequest base64forData:signatures]];    
    NSString *authHeader = [NSString stringWithFormat:@"PTX %@:%@", [pocketTaxiAppDelegate getAccessKey], [ASIHTTPRequest base64forData:signatures]];    
    
    return authHeader;
}

- (NSString*)base64:(NSData*)theData {
	
	const uint8_t* input = (const uint8_t*)[theData bytes];
	NSInteger length = [theData length];
	
    static char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
	
    NSMutableData* data = [NSMutableData dataWithLength:((length + 2) / 3) * 4];
    uint8_t* output = (uint8_t*)data.mutableBytes;
	
	NSInteger i,i2;
    for (i=0; i < length; i += 3) {
        NSInteger value = 0;
		for (i2=0; i2<3; i2++) {
            value <<= 8;
            if (i+i2 < length) {
                value |= (0xFF & input[i+i2]);
            }
        }
		
        NSInteger theIndex = (i / 3) * 4;
        output[theIndex + 0] =                    table[(value >> 18) & 0x3F];
        output[theIndex + 1] =                    table[(value >> 12) & 0x3F];
        output[theIndex + 2] = (i + 1) < length ? table[(value >> 6)  & 0x3F] : '=';
        output[theIndex + 3] = (i + 2) < length ? table[(value >> 0)  & 0x3F] : '=';
    }
	
    return [[[NSString alloc] initWithData:data encoding:NSASCIIStringEncoding] autorelease];
}

@end
