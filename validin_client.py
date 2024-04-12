# {dmitry.chan|john.lampe}@gmail.com
import yaml
import logging
import os
import argparse
import pdb
from logging.handlers import TimedRotatingFileHandler
import validin




def main(myclient):
    domain = args.fqdn_or_ip
    #ret = myclient.domain_history_a_aaaa_ns(domain)
    #ret = myclient.domain_a(domain)
    #ret = myclient.domain_aaaa(domain)
    #ret = myclient.domain_ns(domain)
    #ret = myclient.domain_ns_for(domain)
    #ret = myclient.domain_ptr(domain)
    #ret = myclient.domain_osint(domain)
    #ret = myclient.domain_osint_context(domain)
    #ret = myclient.domain_pivots(domain)

    #ret = myclient.ip_history(domain)
    #ret = myclient.ip_cidr(domain, '24')
    #ret = myclient.ip_ptr(domain)
    #ret = myclient.ip_ptr_cidr(domain, '24')
    #ret = myclient.ip_osint(domain)
    #ret = myclient.ip_osint_cidr(domain, '30')
    #ret = myclient.ip_osint_context(domain)
    #ret = myclient.ip_pivots(domain)
    ret = myclient.ping()
    print(ret)

def configure_logging(log_path, date_format, log_format,
                      log_file_name, retention, log_level='INFO'):
    """
    Configures logging based on the pathing, log level, and formatting provided
    :param retention: Number of days to retain the log
    :param log_file_name: Name of the log file
    :param log_path: Path where the log file will be written
    :param date_format: Format the date will appear as in the log file
    :param log_format: Format the entire log message will appear as in the log
    file
    :param log_level: INFO by default, DEBUG if -v argument is given during
    execution
    :return:
    """

    log_file = os.path.join(log_path, log_file_name)

    if not os.path.isdir(log_path):
        os.mkdir("{}".format(log_path))

    rotate_handler = TimedRotatingFileHandler(filename=log_file,
                                              when='midnight',
                                              interval=1,
                                              backupCount=retention)
    # Will be appended to the rotated log: 20190525
    rotate_suffix = "%Y%m%d"
    rotate_handler.suffix = rotate_suffix

    # Attach formatter
    rotate_handler.setFormatter(logging.Formatter(fmt=log_format,
                                                  datefmt=date_format))

    # noinspection PyArgumentList
    logging.basicConfig(handlers=[rotate_handler],
                        level=log_level)
    logging.getLogger("requests").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)

    return


if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings()

    parser = argparse.ArgumentParser(description='Validin API tool')
    parser.add_argument('-d', action='store', dest='fqdn_or_ip', help='FQDN or IP', required=False)
    parser.add_argument('-c', action='store', dest='config_file', help='Config file', required=False)
    parser.add_argument('-v', action='store_true', dest='verbosity', help='set script verbosity')
    args = parser.parse_args()

    if args.config_file:
        if not os.path.isfile(args.config_file):
            args.config_file = 'validin.yml'
    else:
        args.config_file = 'validin.yml'

    with open(args.config_file) as c:
        config = yaml.safe_load(c)

    logging_conf = config['logging']
    if args.verbosity:
        level = "DEBUG"
    else:
        level = "INFO"

    configure_logging(log_path=logging_conf['path'],
                      date_format=logging_conf['date_format'],
                      log_format=logging_conf['log_format'],
                      log_file_name='validin_api.log',
                      log_level=level,
                      retention=logging_conf['retention'])


    logging.info('Executing Script: {0}'.format(__file__))

    try:
        myclient = validin.Validin(api_key=config['validin']['key'])
    except Exception as e:
        logging.error("Failed to create object : {}. Exiting".format(e))
        exit(0)

    main(myclient)
