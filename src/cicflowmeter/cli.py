from __future__ import annotations

import argparse

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
from sniffer import run

if TYPE_CHECKING:
    from pathlib import Path

OutputMode = Literal['csv', 'url']


@dataclass(slots=True)
class CliConfig:
    """Validated CLI configuration."""

    input_interface: str | None
    input_file: Path | None
    input_directory: Path | None
    output_mode: OutputMode
    output: str
    fields: list[str] | None
    merge: bool
    verbose: bool


class CliArgsModel(BaseModel):
    """Pydantic model used to validate parsed CLI arguments."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    input_interface: str | None = None
    input_file: Path | None = None
    input_directory: Path | None = None
    output_mode: OutputMode
    output: str = Field(min_length=1)
    fields: list[str] | None = None
    merge: bool = False
    verbose: bool = False

    @field_validator('fields', mode='before')
    @classmethod
    def parse_fields(cls, value: object) -> list[str] | None:
        """Convert a comma-separated field string into a normalized list."""
        if value is None:
            return None

        if isinstance(value, str):
            parsed = [item.strip() for item in value.split(',') if item.strip()]
            return parsed or None

        if isinstance(value, list):
            parsed = [str(item).strip() for item in value if str(item).strip()]
            return parsed or None

        raise TypeError('fields must be a comma-separated string or list of strings')

    @model_validator(mode='after')
    def validate_args(self) -> CliArgsModel:
        """Validate cross-field CLI constraints."""
        provided_inputs = [
            self.input_interface is not None,
            self.input_file is not None,
            self.input_directory is not None,
        ]

        if sum(provided_inputs) != 1:
            raise ValueError('Provide exactly one input source: --interface, --file, or --directory.')

        if self.merge and self.input_directory is None:
            raise ValueError('--merge can only be used with --directory mode.')

        if self.input_directory is not None and self.output_mode != 'csv':
            raise ValueError('Directory mode only supports CSV output.')

        return self

    def to_config(self) -> CliConfig:
        """Convert the validated model into a dataclass."""
        return CliConfig(
            input_interface=self.input_interface,
            input_file=self.input_file,
            input_directory=self.input_directory,
            output_mode=self.output_mode,
            output=self.output,
            fields=self.fields,
            merge=self.merge,
            verbose=self.verbose,
        )


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog='cicflowmeter',
        description='Capture network flows from an interface, file, or directory of pcaps.',
    )

    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument(
        '-i',
        '--interface',
        dest='input_interface',
        help='capture online data from INPUT_INTERFACE',
    )
    input_group.add_argument(
        '-f',
        '--file',
        dest='input_file',
        help='capture offline data from INPUT_FILE',
    )
    input_group.add_argument(
        '-d',
        '--directory',
        dest='input_directory',
        help='process all pcap files from INPUT_DIRECTORY',
    )

    output_group = parser.add_mutually_exclusive_group(required=True)
    output_group.add_argument(
        '-c',
        '--csv',
        action='store_const',
        const='csv',
        dest='output_mode',
        help='output flows as csv',
    )
    output_group.add_argument(
        '-u',
        '--url',
        action='store_const',
        const='url',
        dest='output_mode',
        help='output flows as request to url',
    )

    parser.add_argument(
        'output',
        help=('output file name (in csv mode), url (in url mode), or output directory (in directory mode)'),
    )

    parser.add_argument(
        '--fields',
        dest='fields',
        help='comma separated fields to include in output (default: all)',
    )

    parser.add_argument(
        '--merge',
        action='store_true',
        help='merge all pcap files into a single CSV (only works with -d/--directory mode)',
    )

    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='more verbose',
    )

    return parser


def parse_args(argv: list[str] | None = None) -> CliConfig:
    """Parse, validate, and return CLI configuration."""
    parser = build_parser()
    namespace = parser.parse_args(argv)

    try:
        validated = CliArgsModel.model_validate(vars(namespace))
    except ValidationError as exc:
        parser.error(str(exc))

    return validated.to_config()


def main() -> int:
    """Program entrypoint."""
    config = parse_args()
    run(config)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
