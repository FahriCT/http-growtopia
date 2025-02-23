export const ipLimiterConfig = {
    maxRequestsPerSecond: 10, // Maksimal request per detik
    banDuration: 60000, // Durasi pemblokiran dalam milidetik (60 detik)
    permanentBan: true // Jika true, IP akan diblokir permanen
};