from __future__ import annotations

import threading
import time

from pathlib import Path
from typing import TYPE_CHECKING

from scapy.sendrecv import AsyncSniffer

from cicflowmeter.flow_session import FlowSession

if TYPE_CHECKING:
    from .cli import CliConfig


GC_INTERVAL = 1.0  # seconds


def _start_periodic_gc(session: FlowSession, interval: float = GC_INTERVAL) -> None:
    """Start a background thread that periodically garbage-collects flows."""
    stop_event = threading.Event()

    def _gc_loop() -> None:
        while not stop_event.wait(interval):
            try:
                session.garbage_collect(time.time())
            except Exception:
                # Do not let GC thread failures kill the process.
                session.logger.exception('Periodic GC error')

    gc_thread = threading.Thread(
        target=_gc_loop,
        name='flow-gc',
        daemon=True,
    )
    gc_thread.start()

    # Attach to the session so we can stop the thread later.
    setattr(session, '_gc_thread', gc_thread)
    setattr(session, '_gc_stop', stop_event)


def _stop_periodic_gc(session: FlowSession) -> None:
    """Stop the background GC thread if it exists."""
    stop_event = getattr(session, '_gc_stop', None)
    gc_thread = getattr(session, '_gc_thread', None)

    if stop_event is not None:
        stop_event.set()

    if gc_thread is not None:
        gc_thread.join(timeout=2.0)


def create_sniffer(
    input_file: str | None,
    input_interface: str | None,
    output_mode: str,
    output: str,
    input_directory: str | None = None,
    fields: list[str] | None = None,
    verbose: bool = False,
) -> tuple[AsyncSniffer, FlowSession]:
    """Create and configure a sniffer and flow session."""
    assert (
        sum([
            input_file is None,
            input_interface is None,
            input_directory is None,
        ])
        == 2
    ), 'Provide exactly one: interface, file, or directory input'

    session = FlowSession(
        output_mode=output_mode,
        output=output,
        fields=fields,
        verbose=verbose,
    )

    _start_periodic_gc(session, interval=GC_INTERVAL)

    if input_file:
        sniffer = AsyncSniffer(
            offline=input_file,
            filter='ip and (tcp or udp)',
            prn=session.process,
            store=False,
        )
    else:
        sniffer = AsyncSniffer(
            iface=input_interface,
            filter='ip and (tcp or udp)',
            prn=session.process,
            store=False,
        )

    return sniffer, session


def process_directory_merged(
    input_dir: str | Path,
    output_dir: str | Path,
    fields: list[str] | None = None,
    verbose: bool = False,
) -> None:
    """Process all pcap files in a directory and merge output into one CSV."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)

    if not input_path.exists():
        print(f"Error: Input directory '{input_dir}' does not exist")
        return

    if not input_path.is_dir():
        print(f"Error: Input path '{input_dir}' is not a directory")
        return

    if output_path.exists() and output_path.is_file():
        print(f"Error: Output path '{output_dir}' already exists as a file.")
        print('Please provide a directory path for batch processing.')
        return

    try:
        output_path.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        print(f"Error: Could not create output directory '{output_dir}': {exc}")
        return

    pcap_files = list(input_path.glob('*.pcap')) + list(input_path.glob('*.pcapng'))

    if not pcap_files:
        print(f'Error: No pcap files found in {input_dir}')
        return

    output_file = output_path / 'merged_output.csv'
    print(f'Found {len(pcap_files)} pcap file(s) to process')
    print(f'Merging all flows into: {output_file.name}')

    session = FlowSession(
        output_mode='csv',
        output=str(output_file),
        fields=fields,
        verbose=verbose,
    )

    _start_periodic_gc(session, interval=GC_INTERVAL)

    for idx, pcap_file in enumerate(pcap_files, start=1):
        print(f'[{idx}/{len(pcap_files)}] Processing {pcap_file.name}...')

        try:
            sniffer = AsyncSniffer(
                offline=str(pcap_file),
                filter='ip and (tcp or udp)',
                prn=session.process,
                store=False,
            )

            sniffer.start()
            sniffer.join()

            print(f'[{idx}/{len(pcap_files)}] Completed {pcap_file.name}')
        except Exception as exc:
            print(f'Error processing {pcap_file.name}: {exc}')
            continue

    _stop_periodic_gc(session)
    session.flush_flows()

    print(f'\nAll done! Merged output saved to: {output_file}')


def process_directory(
    input_dir: str | Path,
    output_dir: str | Path,
    fields: list[str] | None = None,
    verbose: bool = False,
) -> None:
    """Process all pcap files in a directory into per-file CSV outputs."""
    input_path = Path(input_dir)
    output_path = Path(output_dir)

    if not input_path.exists():
        print(f"Error: Input directory '{input_dir}' does not exist")
        return

    if not input_path.is_dir():
        print(f"Error: Input path '{input_dir}' is not a directory")
        return

    if output_path.exists() and output_path.is_file():
        print(f"Error: Output path '{output_dir}' already exists as a file.")
        print('Please provide a directory path for batch processing.')
        print('Example: cicflowmeter -d ./pcaps/ -c ./output_directory/')
        return

    try:
        output_path.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        print(f"Error: Could not create output directory '{output_dir}': {exc}")
        return

    pcap_files = list(input_path.glob('*.pcap')) + list(input_path.glob('*.pcapng'))

    if not pcap_files:
        print(f'Error: No pcap files found in {input_dir}')
        return

    print(f'Found {len(pcap_files)} pcap file(s) to process')

    for pcap_file in pcap_files:
        output_file = output_path / f'{pcap_file.stem}.csv'
        print(f'Processing {pcap_file.name} -> {output_file.name}')

        try:
            sniffer, session = create_sniffer(
                input_file=str(pcap_file),
                input_interface=None,
                output_mode='csv',
                output=str(output_file),
                input_directory=None,
                fields=fields,
                verbose=verbose,
            )

            sniffer.start()
            sniffer.join()

            _stop_periodic_gc(session)
            session.flush_flows()

            print(f'Completed {pcap_file.name}')
        except Exception as exc:
            print(f'Error processing {pcap_file.name}: {exc}')
            continue

    print(f'\nAll done! Output files saved to: {output_dir}')


def run(config: CliConfig) -> None:
    """Run the sniffer workflow from validated CLI configuration."""
    if config.input_directory is not None:
        if config.merge:
            process_directory_merged(
                input_dir=config.input_directory,
                output_dir=config.output,
                fields=config.fields,
                verbose=config.verbose,
            )
        else:
            process_directory(
                input_dir=config.input_directory,
                output_dir=config.output,
                fields=config.fields,
                verbose=config.verbose,
            )
        return

    sniffer, session = create_sniffer(
        input_file=str(config.input_file) if config.input_file is not None else None,
        input_interface=config.input_interface,
        output_mode=config.output_mode,
        output=config.output,
        input_directory=None,
        fields=config.fields,
        verbose=config.verbose,
    )

    sniffer.start()

    try:
        sniffer.join()
    except KeyboardInterrupt:
        sniffer.stop()
    finally:
        _stop_periodic_gc(session)
        sniffer.join()
        session.flush_flows()
