import hashlib
import uuid
import os
import shutil
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from fastapi.responses import FileResponse, PlainTextResponse
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession

from kavach_ai.backend.pipeline.stage2_static.decompile import extract_apk, DEFAULT_ARTIFACT_ROOT

from kavach_ai.backend.app.db.models import APK, CertInReport
from kavach_ai.backend.app.db.session import get_session
from kavach_ai.backend.app.schemas.contracts import (
    JobStatus,
    JobStatusResponse,
    ReportResponse,
    UploadResponse,
)
from kavach_ai.backend.workers.queue import enqueue_analysis_job

router = APIRouter()

BACKEND_DIR = Path(__file__).resolve().parents[2]
UPLOAD_DIR = BACKEND_DIR / "uploads"


@router.post("/upload", response_model=UploadResponse)
async def upload_apk(
    file: UploadFile,
    session: AsyncSession = Depends(get_session),
) -> UploadResponse:
    contents = await file.read()
    if not contents:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded APK is empty.",
        )

    job_id = str(uuid.uuid4())
    apk_hash = hashlib.sha256(contents).hexdigest()
    filename = file.filename or f"{job_id}.apk"

    existing = await session.exec(select(APK).where(APK.apk_hash == apk_hash))
    existing_apk = existing.one_or_none()
    if existing_apk is not None:
        return UploadResponse(
            job_id=existing_apk.job_id,
            status=JobStatus(existing_apk.status),
            apk_hash=existing_apk.apk_hash,
        )

    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    upload_path = UPLOAD_DIR / f"{job_id}.apk"
    upload_path.write_bytes(contents)

    apk = APK(
        apk_hash=apk_hash,
        job_id=job_id,
        filename=filename,
        file_size=len(contents),
        status=JobStatus.QUEUED.value,
    )
    session.add(apk)
    await session.commit()

    await enqueue_analysis_job(job_id)

    return UploadResponse(
        job_id=job_id,
        status=JobStatus.QUEUED,
        apk_hash=apk_hash,
    )


@router.get("/status/{job_id}", response_model=JobStatusResponse)
async def get_job_status(
    job_id: str,
    session: AsyncSession = Depends(get_session),
) -> JobStatusResponse:
    apk = await _get_apk_by_job_id(job_id, session)
    return JobStatusResponse(
        job_id=apk.job_id,
        status=JobStatus(apk.status),
        apk_hash=apk.apk_hash,
        filename=apk.filename,
        triage_score=apk.triage_score,
        final_score=apk.final_score,
    )


@router.get("/report/{job_id}", response_model=ReportResponse)
async def get_report(
    job_id: str,
    session: AsyncSession = Depends(get_session),
) -> ReportResponse:
    apk = await _get_apk_by_job_id(job_id, session)
    result = await session.exec(
        select(CertInReport).where(CertInReport.apk_hash == apk.apk_hash)
    )
    report = result.one_or_none()
    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Report is not ready for this job.",
        )

    return ReportResponse(
        job_id=apk.job_id,
        apk_hash=apk.apk_hash,
        status=JobStatus(apk.status),
        report=report.mitre_attack_json,
        report_pdf_path=report.report_pdf_path,
        compliance_status=report.compliance_status,
    )


@router.get("/artifacts/{apk_hash}/apk")
async def download_apk(
    apk_hash: str,
):
    apk_path = UPLOAD_DIR / f"{apk_hash}.apk"
    if not apk_path.exists():
        raise HTTPException(status_code=404, detail="APK file not found.")
    return FileResponse(
        path=apk_path,
        filename=f"{apk_hash}.apk",
        media_type="application/vnd.android.package-archive"
    )

@router.get("/artifacts/{apk_hash}/manifest")
async def get_manifest(
    apk_hash: str,
):
    manifest_path = DEFAULT_ARTIFACT_ROOT / apk_hash / "apktool" / "AndroidManifest.xml"
    if not manifest_path.exists():
        raise HTTPException(status_code=404, detail="AndroidManifest.xml not found.")
    
    try:
        content = manifest_path.read_bytes()
        # Check if this is an Android Binary XML (magic bytes: 0x03 0x00 0x08 0x00)
        if content.startswith(b"\x03\x00\x08\x00"):
            from pyaxmlparser.axmlprinter import AXMLPrinter
            axml = AXMLPrinter(content)
            xml_data = axml.get_xml()
            if isinstance(xml_data, bytes):
                return PlainTextResponse(xml_data.decode("utf-8", errors="ignore"))
            return PlainTextResponse(xml_data)
        
        return PlainTextResponse(content.decode("utf-8", errors="ignore"))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read AndroidManifest.xml: {str(e)}")

def _find_main_activity_source(src_dir: Path) -> str:
    # A simple heuristic to find a likely main activity
    for root, _, files in os.walk(src_dir):
        for f in files:
            if "MainActivity" in f:
                return (Path(root) / f).read_text(encoding="utf-8", errors="ignore")
    
    # Fallback to returning any java/smali file as a sample
    for root, _, files in os.walk(src_dir):
        for f in files:
            if f.endswith(".java") or f.endswith(".smali"):
                return (Path(root) / f).read_text(encoding="utf-8", errors="ignore")
    return "No source files found."

@router.get("/artifacts/{apk_hash}/smali")
async def get_smali(
    apk_hash: str,
    download: bool = False,
):
    smali_dir = DEFAULT_ARTIFACT_ROOT / apk_hash / "apktool" / "smali"
    
    if not smali_dir.exists():
        raise HTTPException(status_code=404, detail="Smali source not found.")

    if download:
        zip_path = DEFAULT_ARTIFACT_ROOT / apk_hash / f"{apk_hash}_smali.zip"
        if not zip_path.exists():
            shutil.make_archive(str(zip_path.with_suffix("")), 'zip', str(smali_dir))
        return FileResponse(zip_path, filename=f"{apk_hash}_smali.zip")
    
    return PlainTextResponse(_find_main_activity_source(DEFAULT_ARTIFACT_ROOT / apk_hash / "apktool"))


@router.get("/artifacts/{apk_hash}/java")
async def get_java(
    apk_hash: str,
    download: bool = False,
):
    apk_path = UPLOAD_DIR / f"{apk_hash}.apk"
    java_dir = DEFAULT_ARTIFACT_ROOT / apk_hash / "jadx" / "sources"

    # On-demand extraction
    if not java_dir.exists():
        if not apk_path.exists():
            raise HTTPException(status_code=404, detail="Original APK missing, cannot decompile.")
        extract_apk(apk_path, run_jadx_analysis=True)
        if not java_dir.exists():
             raise HTTPException(status_code=500, detail="Jadx extraction failed.")

    if download:
        zip_path = DEFAULT_ARTIFACT_ROOT / apk_hash / f"{apk_hash}_java.zip"
        if not zip_path.exists():
            shutil.make_archive(str(zip_path.with_suffix("")), 'zip', str(java_dir))
        return FileResponse(zip_path, filename=f"{apk_hash}_java.zip")
    
    return PlainTextResponse(_find_main_activity_source(java_dir))


async def _get_apk_by_job_id(job_id: str, session: AsyncSession) -> APK:
    result = await session.exec(select(APK).where(APK.job_id == job_id))
    apk = result.one_or_none()
    if apk is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Job ID not found.",
        )
    return apk
